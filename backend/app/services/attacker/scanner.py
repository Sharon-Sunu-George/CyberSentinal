"""
Safe, Bounded Web Vulnerability Scanner for CyberSentinal Attacker Agent.
Performs conservative, non-destructive checks against authorized targets:
- Transport / HTTPS & HSTS configuration (CWE-319)
- Essential security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy (CWE-693, CWE-1021, CWE-200)
- CORS header policies (CWE-942)
- Cookie security flags: Secure, HttpOnly (CWE-614, CWE-1004)
- Information disclosure: Server banners, X-Powered-By (CWE-200)
- Safely exposed metadata: robots.txt, RFC 9116 security.txt
- Known CVE correlation based strictly on empirical version evidence
- Configurable scanner service with honest OWASP ZAP discovery and fallback reporting.
"""

import datetime
import http.client
import os
import re
import socket
import ssl
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple

from app.schemas.attacker import FindingEvidence, VulnerabilityFinding
from app.services.attacker.cve_catalog import match_known_cve
from app.services.attacker.ssrf_guard import (
    normalize_target_url,
    resolve_and_verify_ip,
    SSRFProtectionError,
)

DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 512 * 1024  # 512 KB limit to prevent resource exhaustion
MAX_REDIRECT_HOPS = 2
USER_AGENT = "CyberSentinal-Security-Auditor/2.0 (+https://cybersentinel.ai/scanner-policy)"


def detect_proxy_or_tunnel_error(status_code: int, headers: Dict[str, str], body_text: str = "") -> Tuple[bool, Optional[str]]:
    """
    Determines if an HTTP response originates from an intermediary proxy,
    tunnel, or edge gateway error rather than the target web application.
    Identifies Cloudflare, Ngrok, AWS ALB/CloudFront, Nginx/HAProxy reverse proxies.
    """
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    server = lower_headers.get("server", "")
    body_lower = body_text.lower()[:4096]

    # Status codes indicating gateway/reverse proxy failure
    if status_code in (502, 503, 504, 520, 521, 522, 524):
        if "cloudflare" in server or "cf-ray" in lower_headers:
            return True, f"Cloudflare Gateway Error (HTTP {status_code})"
        if "ngrok-error-code" in lower_headers or "ngrok" in body_lower:
            return True, f"Ngrok Tunnel Error (HTTP {status_code})"
        if "awselb" in server or "x-amz-cf-id" in lower_headers or "cloudfront" in body_lower:
            return True, f"AWS Gateway / CloudFront Error (HTTP {status_code})"
        if "nginx" in server:
            return True, f"Nginx Reverse Proxy Bad Gateway / Error (HTTP {status_code})"
        return True, f"Upstream Proxy / Gateway Error (HTTP {status_code})"

    # Tunnel error pages returning 404 or other codes with specific proxy signatures
    if "ngrok-error-code" in lower_headers or "tunnel " in body_lower and "not found" in body_lower:
        return True, "Ngrok Tunnel Inactive or Not Found"
    if "cf-ray" in lower_headers and ("error 52" in body_lower or "web server is down" in body_lower):
        return True, "Cloudflare Host Unreachable"

    return False, None


class SafeHttpResponse:
    """Encapsulates response data from a safe HTTP probe with origin verification."""
    def __init__(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        body_text: str,
        remote_ip: str,
        was_https: bool,
        requested_url: Optional[str] = None,
        final_url: Optional[str] = None,
        redirect_chain: Optional[List[Dict[str, Any]]] = None,
        response_timestamp: Optional[str] = None,
        is_proxy_or_tunnel_error: Optional[bool] = None,
        proxy_or_tunnel_type: Optional[str] = None,
    ):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.body_text = body_text
        self.remote_ip = remote_ip
        self.was_https = was_https
        self.requested_url = requested_url or url
        self.final_url = final_url or url
        self.redirect_chain = redirect_chain or []
        self.response_timestamp = response_timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()

        if is_proxy_or_tunnel_error is None:
            detected, p_type = detect_proxy_or_tunnel_error(status_code, headers, body_text)
            self.is_proxy_or_tunnel_error = detected
            self.proxy_or_tunnel_type = p_type
        else:
            self.is_proxy_or_tunnel_error = is_proxy_or_tunnel_error
            self.proxy_or_tunnel_type = proxy_or_tunnel_type

    def get_header(self, name: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def get_all_headers(self, name: str) -> List[str]:
        matches = []
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                matches.append(v)
        return matches


class SafeHttpClient:
    """
    HTTP client enforcing DNS-rebinding prevention, IP boundary verification,
    response-size constraints, and strict redirect scope confinement.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.timeout = timeout

    def request(
        self,
        url: str,
        method: str = "GET",
        allowed_origin_scheme: Optional[str] = None,
        allowed_origin_host: Optional[str] = None,
        allowed_origin_port: Optional[int] = None,
        redirect_depth: int = 0,
        initial_requested_url: Optional[str] = None,
        redirect_chain: Optional[List[Dict[str, Any]]] = None,
    ) -> SafeHttpResponse:
        if redirect_depth > MAX_REDIRECT_HOPS:
            raise SSRFProtectionError(f"Exceeded maximum redirect limit ({MAX_REDIRECT_HOPS}).")

        req_origin_url = initial_requested_url or url
        chain = list(redirect_chain) if redirect_chain else []

        normalized_url, hostname, port, path = normalize_target_url(url)
        current_scheme = "https" if normalized_url.startswith("https://") else "http"

        target_scheme = allowed_origin_scheme or current_scheme
        target_host = allowed_origin_host or hostname
        target_port = allowed_origin_port or port

        if redirect_depth > 0:
            if hostname != target_host:
                raise SSRFProtectionError(
                    f"Redirect to host '{hostname}' rejected: escapes authorized target host '{target_host}'."
                )

            if target_scheme == "https" and current_scheme == "http":
                raise SSRFProtectionError(
                    f"Redirect scheme downgrade from HTTPS to HTTP on '{hostname}' is prohibited."
                )

            if port != target_port:
                if not (target_port == 80 and port == 443 and current_scheme == "https"):
                    raise SSRFProtectionError(
                        f"Redirect to port {port} rejected: escapes authorized target port scope {target_port}."
                    )

        verified_ip, family = resolve_and_verify_ip(hostname, port)
        is_https = (current_scheme == "https")

        raw_sock = None
        try:
            raw_sock = socket.socket(family, socket.SOCK_STREAM)
            raw_sock.settimeout(self.timeout)
            raw_sock.connect((verified_ip, port))

            if is_https:
                ssl_context = ssl.create_default_context()
                sock = ssl_context.wrap_socket(raw_sock, server_hostname=hostname)
            else:
                sock = raw_sock

            path_and_query = path or "/"
            request_bytes = (
                f"{method} {path_and_query} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("latin-1")

            sock.sendall(request_bytes)

            response_data = bytearray()
            while len(response_data) < MAX_RESPONSE_BYTES:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data.extend(chunk)

            raw_text = response_data.decode("latin-1", errors="replace")
            header_part, _, body_text = raw_text.partition("\r\n\r\n")

            header_lines = header_part.split("\r\n")
            status_line = header_lines[0] if header_lines else "HTTP/1.1 500 Error"
            parts = status_line.split(" ", 2)
            try:
                status_code = int(parts[1]) if len(parts) > 1 else 500
            except ValueError:
                status_code = 500

            headers: Dict[str, str] = {}
            for line in header_lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k_clean = k.strip()
                    v_clean = v.strip()
                    if k_clean.lower() in [h.lower() for h in headers]:
                        for existing_key in list(headers.keys()):
                            if existing_key.lower() == k_clean.lower():
                                headers[existing_key] += f"\n{v_clean}"
                    else:
                        headers[k_clean] = v_clean

            # Handle redirects
            if status_code in (301, 302, 303, 307, 308):
                location = None
                for k, v in headers.items():
                    if k.lower() == "location":
                        location = v.split("\n")[0].strip()
                        break

                if location:
                    next_url = urllib.parse.urljoin(normalized_url, location)
                    chain.append({
                        "from_url": normalized_url,
                        "to_url": next_url,
                        "status_code": status_code,
                    })
                    return self.request(
                        url=next_url,
                        method="GET",
                        allowed_origin_scheme=target_scheme,
                        allowed_origin_host=target_host,
                        allowed_origin_port=target_port,
                        redirect_depth=redirect_depth + 1,
                        initial_requested_url=req_origin_url,
                        redirect_chain=chain,
                    )

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return SafeHttpResponse(
                url=normalized_url,
                status_code=status_code,
                headers=headers,
                body_text=body_text,
                remote_ip=verified_ip,
                was_https=is_https,
                requested_url=req_origin_url,
                final_url=normalized_url,
                redirect_chain=chain,
                response_timestamp=now_iso,
            )
        finally:
            if raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass


def probe_owasp_zap_status() -> Dict[str, Any]:
    """
    Checks if an external OWASP ZAP daemon is running and reachable.
    Reports honest status without fabricating ZAP availability.
    """
    zap_host = os.getenv("ZAP_HOST", "127.0.0.1")
    zap_port = int(os.getenv("ZAP_PORT", "8080"))
    zap_api_key = os.getenv("ZAP_API_KEY", "")

    is_available = False
    zap_version = None
    setup_instructions = (
        "OWASP ZAP daemon is not currently active on {}:{} (optional). "
        "The assessment ran using CyberSentinal's built-in evidence-based passive scanner. "
        "To enable OWASP ZAP integration, install ZAP and run: "
        "'zap.sh -daemon -port 8080 -config api.disablekey=true' (or set ZAP_HOST / ZAP_PORT / ZAP_API_KEY)."
    ).format(zap_host, zap_port)

    # Check connection with brief 0.5s timeout
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((zap_host, zap_port))
        sock.close()

        if result == 0:
            is_available = True
            setup_instructions = f"OWASP ZAP daemon detected and reachable on {zap_host}:{zap_port}."
            # Attempt version read
            try:
                conn = http.client.HTTPConnection(zap_host, zap_port, timeout=1.0)
                path = f"/JSON/core/view/version/?apikey={zap_api_key}" if zap_api_key else "/JSON/core/view/version/"
                conn.request("GET", path)
                resp = conn.getresponse()
                if resp.status == 200:
                    import json
                    body = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    zap_version = body.get("version", "2.x")
                conn.close()
            except Exception:
                zap_version = "Connected"
    except Exception:
        is_available = False

    return {
        "is_available": is_available,
        "service_name": "OWASP ZAP (Zed Attack Proxy)",
        "endpoint": f"{zap_host}:{zap_port}",
        "version": zap_version,
        "instructions": setup_instructions,
    }


class EvidenceBasedScanner:
    """
    Executes safe, non-destructive evidence-based security auditing.
    Never confirms a vulnerability without observed proof.
    """

    def __init__(self, client: Optional[SafeHttpClient] = None):
        self.client = client or SafeHttpClient()
        self.scanner_name = "CyberSentinal Evidence-Based Scanner v2.0"

    def scan(self, target_url: str) -> Tuple[List[VulnerabilityFinding], Dict[str, Any]]:
        normalized_url, hostname, port, path = normalize_target_url(target_url)
        findings: List[VulnerabilityFinding] = []
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Check OWASP ZAP availability
        zap_status = probe_owasp_zap_status()

        scan_meta: Dict[str, Any] = {
            "target_url": target_url,
            "normalized_url": normalized_url,
            "target_host": hostname,
            "target_ip": None,
            "scanned_at": now,
            "scanner_name": self.scanner_name,
            "is_inconclusive": False,
            "allows_retry": False,
            "scanner_info": {
                "engine": self.scanner_name,
                "mode": "passive-safe",
                "zap_integration": zap_status,
                "checks_executed": [
                    "Transport Security & HTTPS (CWE-319)",
                    "Strict-Transport-Security HSTS (CWE-319/CWE-523)",
                    "Content-Security-Policy (CWE-693)",
                    "X-Content-Type-Options nosniff (CWE-693)",
                    "X-Frame-Options / frame-ancestors Clickjacking (CWE-1021)",
                    "Referrer-Policy Header (CWE-200)",
                    "Permissions-Policy Header (CWE-693)",
                    "Cross-Origin Resource Sharing (CORS) Policy (CWE-942)",
                    "Cookie Security Flags (Secure & HttpOnly) (CWE-614/CWE-1004)",
                    "Server & Runtime Banner Information Disclosure (CWE-200)",
                    "Sensitive Endpoints in robots.txt (CWE-200)",
                    "RFC 9116 security.txt Contact Configuration",
                    "CVE Knowledge Correlation (Exact Component Version Evidence)",
                ],
            },
            "scope_limitations": (
                "Scan is strictly limited to authorized external HTTP/TLS non-destructive auditing. "
                "Checks include response header analysis, TLS configuration, cookie flags, exposed metadata files, "
                "and component version matching. Does NOT perform invasive payload injection, automated exploit delivery, "
                "fuzzing, or password cracking."
            ),
        }

        # Probe 1: Primary Target Page
        try:
            main_resp = self.client.request(normalized_url, allowed_origin_host=hostname)
            scan_meta["target_ip"] = main_resp.remote_ip
            scan_meta["status_code"] = main_resp.status_code
            scan_meta["final_url"] = main_resp.final_url
            scan_meta["requested_url"] = main_resp.requested_url
        except Exception as e:
            scan_meta["error"] = str(e)
            scan_meta["is_inconclusive"] = True
            scan_meta["allows_retry"] = True
            # Connection or network failure finding
            findings.append(
                VulnerabilityFinding(
                    id="VULN-SCAN-CONNECTION-FAILED",
                    title="Target Connection Failed / Inaccessible",
                    category="Transport Security",
                    severity="Low",
                    confidence="High",
                    affected_url_or_component=target_url,
                    evidence=FindingEvidence(
                        check_type="connection_probe",
                        observed_data={"error": str(e), "target_url": target_url},
                        raw_snippet=f"Failed to establish network connection to target: {str(e)}",
                        status_code=None,
                        requested_url=target_url,
                        final_url=target_url,
                        observed_headers={},
                        check_result="Scan error",
                        confidence_reason="Direct TCP connection, TLS handshake, or socket timeout error prevented receiving HTTP response.",
                        is_inferred=False,
                        response_timestamp=now,
                    ),
                    potential_impact="Security assessment could not complete because the target host is unreachable, down, or rejecting incoming TCP connections.",
                    remediation="Verify target host availability, firewall configuration, DNS records, and retry the assessment.",
                    cwe_id=None,
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=now,
                    references=[],
                    is_confirmed=True,
                    validation_status="Scan error",
                )
            )
            return findings, scan_meta

        # Check for proxy / tunnel error or 502/503/504 gateway responses
        if main_resp.is_proxy_or_tunnel_error or main_resp.status_code in (502, 503, 504, 520, 521, 522, 524):
            scan_meta["is_inconclusive"] = True
            scan_meta["allows_retry"] = True
            reason_label = main_resp.proxy_or_tunnel_type or f"Gateway Error (HTTP {main_resp.status_code})"
            findings.append(
                VulnerabilityFinding(
                    id="VULN-SCAN-GATEWAY-PROXY-ERROR",
                    title=f"Scan Inconclusive: Upstream {reason_label}",
                    category="Transport Security",
                    severity="Low",
                    confidence="High",
                    affected_url_or_component=main_resp.final_url,
                    evidence=FindingEvidence(
                        check_type="proxy_gateway_check",
                        observed_data={
                            "status_code": main_resp.status_code,
                            "proxy_or_tunnel_type": main_resp.proxy_or_tunnel_type,
                            "server": main_resp.get_header("Server") or "unknown",
                        },
                        raw_snippet=f"HTTP {main_resp.status_code} received from intermediate gateway: {reason_label}. Application response was not reached.",
                        status_code=main_resp.status_code,
                        requested_url=main_resp.requested_url,
                        final_url=main_resp.final_url,
                        observed_headers={k: v for k, v in main_resp.headers.items() if k.lower() in ("server", "cf-ray", "via", "x-cache", "ngrok-error-code")},
                        check_result="Inconclusive",
                        confidence_reason="HTTP response originated from an intermediate reverse proxy or edge tunnel failure. Application security headers cannot be verified from a gateway error page.",
                        is_inferred=False,
                        response_timestamp=main_resp.response_timestamp,
                    ),
                    potential_impact="The target web server is offline, unhealthy, or rejecting connections from the edge proxy. Target security headers cannot be accurately assessed.",
                    remediation="Ensure upstream web service is running and accessible to the edge proxy/tunnel, then retry the assessment.",
                    cwe_id=None,
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=now,
                    references=[],
                    is_confirmed=True,
                    validation_status="Inconclusive",
                )
            )
            return findings, scan_meta

        # Execute standard checks against valid application responses
        # Check 1: HTTPS & Transport Security
        self._check_transport_security(main_resp, findings, now)

        # Check 2: Essential Security Headers (CSP, X-Content-Type-Options, XFO)
        self._check_security_headers(main_resp, findings, now)

        # Check 3: Privacy & Exposure Headers (Referrer-Policy, Permissions-Policy)
        self._check_privacy_and_permissions_headers(main_resp, findings, now)

        # Check 4: CORS Configuration
        self._check_cors_policy(main_resp, findings, now)

        # Check 5: Cookie Security Flags
        self._check_cookie_flags(main_resp, findings, now)

        # Check 6: Information Disclosure (Server & X-Powered-By)
        self._check_information_disclosure(main_resp, findings, now)

        # Check 7: Safely Exposed Resources (/robots.txt)
        self._check_robots_txt(hostname, port, main_resp.was_https, findings, now)

        # Check 8: Security.txt Presence
        self._check_security_txt(hostname, port, main_resp.was_https, findings, now)

        # Deduplicate findings by ID
        unique_findings: List[VulnerabilityFinding] = []
        seen_ids = set()
        for f in findings:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                unique_findings.append(f)

        return unique_findings, scan_meta

    def _check_transport_security(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding], now: Optional[str] = None):
        ts = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not resp.was_https:
            findings.append(
                VulnerabilityFinding(
                    id="VULN-TLS-NO-HTTPS",
                    title="Cleartext HTTP Scheme in Use",
                    category="Transport Security",
                    severity="High",
                    confidence="High",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="tls_configuration",
                        observed_data={"scheme": "http", "status": resp.status_code},
                        raw_snippet=f"Target URL is served over unencrypted HTTP: {resp.url}",
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={},
                        check_result="Confirmed observation",
                        confidence_reason="Observed connection protocol is plain unencrypted HTTP. All network traffic is sent in cleartext.",
                        is_inferred=False,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Network eavesdroppers and man-in-the-middle attackers can intercept or modify transmitted credentials, session cookies, and sensitive payloads.",
                    remediation="Migrate site to HTTPS, redirect all HTTP port 80 traffic to HTTPS port 443, and configure HSTS.",
                    cwe_id="CWE-319",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                    ],
                    is_confirmed=True,
                    validation_status="Confirmed Observation",
                )
            )
        else:
            # HSTS is evaluated ONLY on HTTPS connections per RFC 6797 Section 7.2
            hsts = resp.get_header("Strict-Transport-Security")
            if not hsts:
                findings.append(
                    VulnerabilityFinding(
                        id="VULN-TLS-MISSING-HSTS",
                        title="Missing HTTP Strict Transport Security (HSTS)",
                        category="Transport Security",
                        severity="Medium",
                        confidence="High",
                        affected_url_or_component=resp.url,
                        evidence=FindingEvidence(
                            check_type="security_headers",
                            observed_data={"missing_header": "Strict-Transport-Security", "scheme": "https"},
                            raw_snippet="Response headers do not include 'Strict-Transport-Security'.",
                            status_code=resp.status_code,
                            requested_url=resp.requested_url,
                            final_url=resp.final_url,
                            observed_headers={k: v for k, v in resp.headers.items() if "transport" in k.lower() or "strict" in k.lower()},
                            check_result="Potential risk",
                            confidence_reason="Evaluated on a secure HTTPS response. Strict-Transport-Security header is completely absent, allowing SSL-stripping downgrades.",
                            is_inferred=True,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact="Users connecting over insecure networks can be downgraded to unencrypted HTTP via SSL-stripping attacks on subsequent visits.",
                        remediation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server configuration.",
                        cwe_id="CWE-319",
                        cve_id=None,
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            "https://datatracker.ietf.org/doc/html/rfc6797",
                            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                        ],
                        is_confirmed=True,
                        validation_status="Security Weakness",
                    )
                )

    def _check_security_headers(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding], now: Optional[str] = None):
        ts = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
        csp = resp.get_header("Content-Security-Policy")
        if not csp:
            findings.append(
                VulnerabilityFinding(
                    id="VULN-SEC-HDR-NO-CSP",
                    title="Missing Content Security Policy (CSP)",
                    category="Security Headers",
                    severity="Medium",
                    confidence="High",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="security_headers",
                        observed_data={"missing_header": "Content-Security-Policy"},
                        raw_snippet="Response header 'Content-Security-Policy' is absent from the target HTTP response.",
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={},
                        check_result="Potential risk",
                        confidence_reason="Finding is based solely on the absence of the Content-Security-Policy header in observed headers. No direct script injection was tested.",
                        is_inferred=True,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Increases susceptibility to Cross-Site Scripting (XSS), unauthorized inline script execution, and untrusted asset loading.",
                    remediation="Define a restrictive Content Security Policy (e.g., default-src 'self'; script-src 'self'; object-src 'none').",
                    cwe_id="CWE-693",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    ],
                    is_confirmed=True,
                    validation_status="Security Weakness",
                )
            )

        xcto = resp.get_header("X-Content-Type-Options")
        if not xcto:
            findings.append(
                VulnerabilityFinding(
                    id="VULN-SEC-HDR-NO-NOSNIFF",
                    title="Missing X-Content-Type-Options Header",
                    category="Security Headers",
                    severity="Low",
                    confidence="High",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="security_headers",
                        observed_data={"header_value": "absent"},
                        raw_snippet="Response header 'X-Content-Type-Options' is absent.",
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={},
                        check_result="Potential risk",
                        confidence_reason="X-Content-Type-Options is missing entirely; browser may sniff MIME types away from declared Content-Type.",
                        is_inferred=True,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Browsers may MIME-sniff response bodies away from the declared Content-Type, potentially executing non-executable files as JavaScript or HTML.",
                    remediation="Add 'X-Content-Type-Options: nosniff' to web server response headers.",
                    cwe_id="CWE-693",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                    ],
                    is_confirmed=True,
                    validation_status="Security Weakness",
                )
            )
        elif "nosniff" not in xcto.lower():
            findings.append(
                VulnerabilityFinding(
                    id="VULN-SEC-HDR-INVALID-NOSNIFF",
                    title="Invalid X-Content-Type-Options Header Value",
                    category="Security Headers",
                    severity="Low",
                    confidence="High",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="security_headers",
                        observed_data={"header_value": xcto},
                        raw_snippet=f"Observed X-Content-Type-Options: '{xcto}' (expected 'nosniff')",
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={"x-content-type-options": xcto},
                        check_result="Confirmed observation",
                        confidence_reason=f"Header is present with value '{xcto}', which does not contain the mandatory 'nosniff' directive.",
                        is_inferred=False,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Browsers will ignore invalid X-Content-Type-Options values and continue MIME-sniffing payloads.",
                    remediation="Change 'X-Content-Type-Options' value to exactly 'nosniff'.",
                    cwe_id="CWE-693",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                    ],
                    is_confirmed=True,
                    validation_status="Security Weakness",
                )
            )

        xfo = resp.get_header("X-Frame-Options")
        has_effective_xfo = bool(xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"))

        has_effective_frame_ancestors = False
        if csp:
            for directive in csp.split(";"):
                parts = directive.strip().split()
                if parts and parts[0].lower() == "frame-ancestors":
                    if len(parts) > 1 and parts[1].strip() not in ("*", '""', "''"):
                        has_effective_frame_ancestors = True
                    break

        # Clickjacking is considered mitigated if EITHER effective XFO OR CSP frame-ancestors is present
        if not has_effective_xfo and not has_effective_frame_ancestors:
            findings.append(
                VulnerabilityFinding(
                    id="VULN-SEC-HDR-NO-XFO",
                    title="Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)",
                    category="Security Headers",
                    severity="Medium",
                    confidence="High",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="security_headers",
                        observed_data={
                            "x_frame_options": xfo or "absent",
                            "has_effective_xfo": has_effective_xfo,
                            "has_effective_frame_ancestors": has_effective_frame_ancestors,
                            "raw_csp": csp or "absent",
                        },
                        raw_snippet=(
                            f"X-Frame-Options: '{xfo or 'absent'}'; "
                            f"CSP frame-ancestors: {'configured' if has_effective_frame_ancestors else 'absent/ineffective'}"
                        ),
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={
                            k: v for k, v in resp.headers.items()
                            if k.lower() in ("x-frame-options", "content-security-policy")
                        },
                        check_result="Potential risk",
                        confidence_reason="Evaluated both X-Frame-Options and Content-Security-Policy frame-ancestors. Neither mechanism provides framing restrictions.",
                        is_inferred=True,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Adversary can embed this page inside an invisible iframe on a malicious website to trick users into unintended actions (Clickjacking).",
                    remediation="Configure 'X-Frame-Options: DENY' or 'SAMEORIGIN', or declare CSP 'frame-ancestors 'self''.",
                    cwe_id="CWE-1021",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                    ],
                    is_confirmed=True,
                    validation_status="Security Weakness",
                )
            )

    def _check_privacy_and_permissions_headers(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding], now: Optional[str] = None):
        ts = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
        referrer_policy = resp.get_header("Referrer-Policy")
        if not referrer_policy:
            findings.append(
                VulnerabilityFinding(
                    id="VULN-SEC-HDR-NO-REFERRER",
                    title="Hardening Observation: Missing Referrer-Policy Header",
                    category="Security Headers",
                    severity="Low",
                    confidence="High",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="security_headers",
                        observed_data={"missing_header": "Referrer-Policy"},
                        raw_snippet="Response header 'Referrer-Policy' is absent from HTTP response.",
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={},
                        check_result="Potential risk",
                        confidence_reason="Absence of explicit Referrer-Policy is a hardening observation; modern browsers default to strict-origin-when-cross-origin, but explicit policy is recommended.",
                        is_inferred=True,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Browsers may leak sensitive URL parameters or internal path structures in the Referer header to third-party domains.",
                    remediation="Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                    cwe_id="CWE-200",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                    ],
                    is_confirmed=True,
                    validation_status="Informational Observation",
                )
            )

        permissions_policy = resp.get_header("Permissions-Policy") or resp.get_header("Feature-Policy")
        if not permissions_policy:
            findings.append(
                VulnerabilityFinding(
                    id="VULN-SEC-HDR-NO-PERMISSIONS",
                    title="Hardening Observation: Missing Permissions-Policy Header",
                    category="Security Headers",
                    severity="Low",
                    confidence="Medium",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="security_headers",
                        observed_data={"missing_header": "Permissions-Policy"},
                        raw_snippet="Response header 'Permissions-Policy' (and legacy 'Feature-Policy') is absent.",
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={},
                        check_result="Potential risk",
                        confidence_reason="Hardware features are not explicitly locked down. Recommended hardening observation to restrict camera, microphone, and geolocation.",
                        is_inferred=True,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Browser hardware APIs (camera, microphone, geolocation) are not explicitly restricted, increasing risk if a subresource or third-party script is compromised.",
                    remediation="Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to limit sensitive browser API access.",
                    cwe_id="CWE-693",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    ],
                    is_confirmed=True,
                    validation_status="Informational Observation",
                )
            )

    def _check_cors_policy(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding], now: Optional[str] = None):
        ts = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
        acao = resp.get_header("Access-Control-Allow-Origin")
        acac = resp.get_header("Access-Control-Allow-Credentials")

        if acao == "*" and acac and acac.lower() == "true":
            findings.append(
                VulnerabilityFinding(
                    id="VULN-CORS-WILDCARD-CREDENTIALS",
                    title="Overly Permissive CORS Policy with Credentials Allowed",
                    category="Access Control",
                    severity="High",
                    confidence="High",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="cors",
                        observed_data={"Access-Control-Allow-Origin": acao, "Access-Control-Allow-Credentials": acac},
                        raw_snippet=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
                        check_result="Confirmed observation",
                        confidence_reason="Direct empirical observation of wildcard origin configured with credentials flag enabled.",
                        is_inferred=False,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Untrusted origins can read authenticated API responses and compromise sensitive user session data.",
                    remediation="Never combine wildcard '*' Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true. Specify trusted whitelist origins explicitly.",
                    cwe_id="CWE-942",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
                    ],
                    is_confirmed=True,
                    validation_status="Confirmed Observation",
                )
            )
        elif acao == "*":
            findings.append(
                VulnerabilityFinding(
                    id="VULN-CORS-WILDCARD",
                    title="Wildcard Access-Control-Allow-Origin Header",
                    category="Access Control",
                    severity="Low",
                    confidence="High",
                    affected_url_or_component=resp.url,
                    evidence=FindingEvidence(
                        check_type="cors",
                        observed_data={"Access-Control-Allow-Origin": acao},
                        raw_snippet=f"Access-Control-Allow-Origin: {acao}",
                        status_code=resp.status_code,
                        requested_url=resp.requested_url,
                        final_url=resp.final_url,
                        observed_headers={"access-control-allow-origin": acao},
                        check_result="Confirmed observation",
                        confidence_reason="Direct observation of wildcard Access-Control-Allow-Origin header.",
                        is_inferred=False,
                        response_timestamp=resp.response_timestamp,
                    ),
                    potential_impact="Any external domain can read unauthenticated response payloads from this endpoint.",
                    remediation="If this endpoint is not meant as a public read-only API, restrict Access-Control-Allow-Origin to authorized corporate domains.",
                    cwe_id="CWE-942",
                    cve_id=None,
                    scanner_name=self.scanner_name,
                    scanned_at=ts,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    ],
                    is_confirmed=True,
                    validation_status="Informational Observation",
                )
            )

    def _check_cookie_flags(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding], now: Optional[str] = None):
        ts = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
        set_cookie_raw = resp.get_header("set-cookie")
        if not set_cookie_raw:
            return

        cookies = [c.strip() for c in set_cookie_raw.split("\n") if c.strip()]
        for cookie_str in cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            name_val = parts[0]
            cookie_name = name_val.split("=")[0].strip() if "=" in name_val else name_val
            lower_parts = [p.lower() for p in parts[1:]]

            is_secure = any("secure" == p for p in lower_parts)
            if not is_secure and resp.was_https:
                findings.append(
                    VulnerabilityFinding(
                        id=f"VULN-COOKIE-NO-SECURE-{cookie_name[:12]}",
                        title=f"Cookie '{cookie_name}' Missing Secure Flag",
                        category="Session Management",
                        severity="Medium",
                        confidence="High",
                        affected_url_or_component=f"Cookie: {cookie_name}",
                        evidence=FindingEvidence(
                            check_type="cookie_flags",
                            observed_data={"cookie": cookie_name, "raw": cookie_str},
                            raw_snippet=f"Set-Cookie: {cookie_str}",
                            status_code=resp.status_code,
                            requested_url=resp.requested_url,
                            final_url=resp.final_url,
                            observed_headers={"set-cookie": cookie_str},
                            check_result="Confirmed observation",
                            confidence_reason="Observed Set-Cookie response header issued over HTTPS without the Secure flag.",
                            is_inferred=False,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact="Cookie will be transmitted in cleartext if user ever clicks an HTTP link to the same origin, exposing session tokens.",
                        remediation=f"Append '; Secure' attribute when issuing Set-Cookie for '{cookie_name}'.",
                        cwe_id="CWE-614",
                        cve_id=None,
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies-attributes",
                        ],
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )

            is_httponly = any("httponly" == p for p in lower_parts)
            if not is_httponly:
                findings.append(
                    VulnerabilityFinding(
                        id=f"VULN-COOKIE-NO-HTTPONLY-{cookie_name[:12]}",
                        title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                        category="Session Management",
                        severity="Low",
                        confidence="High",
                        affected_url_or_component=f"Cookie: {cookie_name}",
                        evidence=FindingEvidence(
                            check_type="cookie_flags",
                            observed_data={"cookie": cookie_name, "raw": cookie_str},
                            raw_snippet=f"Set-Cookie: {cookie_str}",
                            status_code=resp.status_code,
                            requested_url=resp.requested_url,
                            final_url=resp.final_url,
                            observed_headers={"set-cookie": cookie_str},
                            check_result="Confirmed observation",
                            confidence_reason="Observed Set-Cookie response header does not contain the HttpOnly directive.",
                            is_inferred=False,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact="Client-side scripts can read this cookie via document.cookie, magnifying the impact of any Cross-Site Scripting (XSS) vulnerability.",
                        remediation=f"Append '; HttpOnly' attribute to '{cookie_name}' if not required by client-side JavaScript.",
                        cwe_id="CWE-1004",
                        cve_id=None,
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#httponly-flag",
                        ],
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )

    def _check_information_disclosure(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding], now: Optional[str] = None):
        ts = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
        server_banner = resp.get_header("Server")
        if server_banner:
            has_version = bool(re.search(r"\d+\.\d+", server_banner))
            matched_cve = match_known_cve(server_banner) if has_version else None

            if matched_cve:
                findings.append(
                    VulnerabilityFinding(
                        id=f"VULN-CVE-{matched_cve['cve_id']}",
                        title=f"Potential {matched_cve['title']} ({matched_cve['cve_id']}) - Requires Validation",
                        category="Outdated Software",
                        severity=matched_cve["severity"],
                        confidence="Medium",
                        affected_url_or_component=f"Server Banner: {server_banner}",
                        evidence=FindingEvidence(
                            check_type="info_disclosure",
                            observed_data={
                                "disclosed_banner": server_banner,
                                "matched_component": matched_cve["title"],
                                "matched_cve": matched_cve["cve_id"],
                            },
                            raw_snippet=f"Server: {server_banner}",
                            status_code=resp.status_code,
                            requested_url=resp.requested_url,
                            final_url=resp.final_url,
                            observed_headers={"server": server_banner},
                            check_result="Potential risk",
                            confidence_reason="Inferred risk based on exact version banner match; vendor backported patches may be present without version changes.",
                            is_inferred=True,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact=(
                            f"Observed server banner indicates component version mapped to {matched_cve['cve_id']}. "
                            f"If active software is unpatched and lacks backported vendor fixes: {matched_cve['impact']}"
                        ),
                        remediation=matched_cve["remediation"],
                        cwe_id="CWE-200",
                        cve_id=matched_cve["cve_id"],
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            f"https://nvd.nist.gov/vuln/detail/{matched_cve['cve_id']}",
                        ],
                        is_confirmed=False,
                        validation_status="Requires Further Validation",
                    )
                )
            elif has_version:
                findings.append(
                    VulnerabilityFinding(
                        id="VULN-INFO-SERVER-VERSION",
                        title=f"Web Server Version Disclosed: '{server_banner}'",
                        category="Information Disclosure",
                        severity="Low",
                        confidence="High",
                        affected_url_or_component=resp.url,
                        evidence=FindingEvidence(
                            check_type="info_disclosure",
                            observed_data={"server_banner": server_banner},
                            raw_snippet=f"Server: {server_banner}",
                            status_code=resp.status_code,
                            requested_url=resp.requested_url,
                            final_url=resp.final_url,
                            observed_headers={"server": server_banner},
                            check_result="Confirmed observation",
                            confidence_reason="Direct empirical observation of Server header containing granular version string.",
                            is_inferred=False,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact="Revealing exact software and version identifiers enables adversaries to query exploit databases for version-specific exploits.",
                        remediation="Configure web server to suppress granular version banners (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).",
                        cwe_id="CWE-200",
                        cve_id=None,
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            "https://owasp.org/www-community/attacks/Fingerprinting",
                        ],
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )

        powered_by = resp.get_header("X-Powered-By")
        if powered_by:
            matched_cve = match_known_cve(powered_by)
            if matched_cve:
                findings.append(
                    VulnerabilityFinding(
                        id=f"VULN-CVE-{matched_cve['cve_id']}",
                        title=f"Potential {matched_cve['title']} ({matched_cve['cve_id']}) - Requires Validation",
                        category="Outdated Software",
                        severity=matched_cve["severity"],
                        confidence="Medium",
                        affected_url_or_component=f"X-Powered-By Banner: {powered_by}",
                        evidence=FindingEvidence(
                            check_type="info_disclosure",
                            observed_data={
                                "x_powered_by": powered_by,
                                "matched_component": matched_cve["title"],
                                "matched_cve": matched_cve["cve_id"],
                            },
                            raw_snippet=f"X-Powered-By: {powered_by}",
                            status_code=resp.status_code,
                            requested_url=resp.requested_url,
                            final_url=resp.final_url,
                            observed_headers={"x-powered-by": powered_by},
                            check_result="Potential risk",
                            confidence_reason="Inferred risk based on runtime framework version banner.",
                            is_inferred=True,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact=(
                            f"Observed runtime banner indicates component version mapped to {matched_cve['cve_id']}. "
                            f"If active software is unpatched and lacks backported vendor fixes: {matched_cve['impact']}"
                        ),
                        remediation=matched_cve["remediation"],
                        cwe_id="CWE-200",
                        cve_id=matched_cve["cve_id"],
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            f"https://nvd.nist.gov/vuln/detail/{matched_cve['cve_id']}",
                        ],
                        is_confirmed=False,
                        validation_status="Requires Further Validation",
                    )
                )
            else:
                findings.append(
                    VulnerabilityFinding(
                        id="VULN-INFO-X-POWERED-BY",
                        title=f"Application Technology Disclosed: '{powered_by}'",
                        category="Information Disclosure",
                        severity="Low",
                        confidence="High",
                        affected_url_or_component=resp.url,
                        evidence=FindingEvidence(
                            check_type="info_disclosure",
                            observed_data={"x_powered_by": powered_by},
                            raw_snippet=f"X-Powered-By: {powered_by}",
                            status_code=resp.status_code,
                            requested_url=resp.requested_url,
                            final_url=resp.final_url,
                            observed_headers={"x-powered-by": powered_by},
                            check_result="Confirmed observation",
                            confidence_reason="Direct empirical observation of framework technology disclosed in X-Powered-By header.",
                            is_inferred=False,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact="Assists attackers in fingerprinting backend frameworks and tailoring exploits to framework vulnerabilities.",
                        remediation="Disable the X-Powered-By header in application server or framework configuration (e.g., app.disable('x-powered-by') in Express).",
                        cwe_id="CWE-200",
                        cve_id=None,
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
                        ],
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )

    def _check_robots_txt(self, host: str, port: int, is_https: bool, findings: List[VulnerabilityFinding], now: Optional[str] = None):
        ts = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
        scheme = "https" if is_https else "http"
        port_suffix = f":{port}" if (is_https and port != 443) or (not is_https and port != 80) else ""
        robots_url = f"{scheme}://{host}{port_suffix}/robots.txt"

        try:
            resp = self.client.request(robots_url, allowed_origin_host=host)
            if resp.status_code == 200 and resp.body_text:
                sensitive_patterns = [r"/admin", r"/backup", r"/private", r"/config", r"/internal", r"/api/v1/internal"]
                disallowed_paths = []
                for line in resp.body_text.splitlines():
                    if line.strip().lower().startswith("disallow:"):
                        path_entry = line.split(":", 1)[1].strip()
                        for pat in sensitive_patterns:
                            if re.search(pat, path_entry, re.IGNORECASE):
                                disallowed_paths.append(path_entry)

                if disallowed_paths:
                    findings.append(
                        VulnerabilityFinding(
                            id="VULN-INFO-ROBOTS-SENSITIVE-PATHS",
                            title="Sensitive Endpoints Disclosed in robots.txt",
                            category="Information Disclosure",
                            severity="Low",
                            confidence="High",
                            affected_url_or_component=robots_url,
                            evidence=FindingEvidence(
                                check_type="robots_txt",
                                observed_data={"disallowed_sensitive_paths": disallowed_paths[:5]},
                                raw_snippet=f"Disallowed paths found: {', '.join(disallowed_paths[:5])}",
                                status_code=resp.status_code,
                                requested_url=robots_url,
                                final_url=resp.final_url,
                                observed_headers={"content-type": resp.get_header("content-type") or ""},
                                check_result="Confirmed observation",
                                confidence_reason="Direct observation of administrative or internal path patterns listed in robots.txt Disallow directives.",
                                is_inferred=False,
                                response_timestamp=resp.response_timestamp,
                            ),
                            potential_impact="robots.txt reveals administrative or internal directory structures to search engines and public threat actors.",
                            remediation="Do not rely on robots.txt to hide sensitive endpoints. Implement proper access control and remove sensitive path entries.",
                            cwe_id="CWE-200",
                            cve_id=None,
                            scanner_name=self.scanner_name,
                            scanned_at=ts,
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage",
                            ],
                            is_confirmed=True,
                            validation_status="Confirmed Observation",
                        )
                    )
        except Exception:
            pass

    def _check_security_txt(self, host: str, port: int, is_https: bool, findings: List[VulnerabilityFinding], now: Optional[str] = None):
        ts = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
        scheme = "https" if is_https else "http"
        port_suffix = f":{port}" if (is_https and port != 443) or (not is_https and port != 80) else ""
        sectxt_url = f"{scheme}://{host}{port_suffix}/.well-known/security.txt"

        try:
            resp = self.client.request(sectxt_url, allowed_origin_host=host)
            content_type = (resp.get_header("content-type") or "").lower()

            # Case A: 404 Not Found -> Missing RFC 9116 security.txt
            if resp.status_code == 404:
                findings.append(
                    VulnerabilityFinding(
                        id="VULN-BEST-PRACTICE-NO-SECURITY-TXT",
                        title="Missing Security Disclosure Contact (security.txt)",
                        category="Security Best Practice",
                        severity="Info",
                        confidence="High",
                        affected_url_or_component=sectxt_url,
                        evidence=FindingEvidence(
                            check_type="security_best_practice",
                            observed_data={"status_code": 404, "endpoint": sectxt_url},
                            raw_snippet=f"GET /.well-known/security.txt returned HTTP 404 Not Found",
                            status_code=404,
                            requested_url=sectxt_url,
                            final_url=resp.final_url,
                            observed_headers={"content-type": resp.get_header("content-type") or ""},
                            check_result="Confirmed observation",
                            confidence_reason="RFC 9116 security.txt endpoint returned HTTP 404 indicating no security disclosure contact is published.",
                            is_inferred=False,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact="Security researchers discovering vulnerabilities lack an official, standardized reporting channel (RFC 9116).",
                        remediation="Publish a valid RFC 9116 security.txt file at /.well-known/security.txt with Contact and Expires directives.",
                        cwe_id="CWE-1059",
                        cve_id=None,
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            "https://www.rfc-editor.org/rfc/rfc9116",
                        ],
                        is_confirmed=True,
                        validation_status="Informational Observation",
                    )
                )
            # Case B: Inaccessible (401, 403, 5xx) -> Inconclusive
            elif resp.status_code in (401, 403) or resp.status_code >= 500:
                findings.append(
                    VulnerabilityFinding(
                        id="VULN-BEST-PRACTICE-INACCESSIBLE-SECURITY-TXT",
                        title="Inaccessible Security Disclosure Endpoint (security.txt)",
                        category="Security Best Practice",
                        severity="Info",
                        confidence="Medium",
                        affected_url_or_component=sectxt_url,
                        evidence=FindingEvidence(
                            check_type="security_best_practice",
                            observed_data={"status_code": resp.status_code, "endpoint": sectxt_url},
                            raw_snippet=f"GET /.well-known/security.txt returned HTTP {resp.status_code} (Inaccessible)",
                            status_code=resp.status_code,
                            requested_url=sectxt_url,
                            final_url=resp.final_url,
                            observed_headers={"content-type": resp.get_header("content-type") or ""},
                            check_result="Inconclusive",
                            confidence_reason=f"Endpoint returned HTTP {resp.status_code}. Content could not be accessed to verify RFC 9116 compliance.",
                            is_inferred=False,
                            response_timestamp=resp.response_timestamp,
                        ),
                        potential_impact="Access to the RFC 9116 security disclosure file is restricted or rejected by authorization rules or gateway errors.",
                        remediation="Ensure /.well-known/security.txt is publicly accessible without authentication or IP restrictions.",
                        cwe_id="CWE-1059",
                        cve_id=None,
                        scanner_name=self.scanner_name,
                        scanned_at=ts,
                        references=[
                            "https://www.rfc-editor.org/rfc/rfc9116",
                        ],
                        is_confirmed=False,
                        validation_status="Inconclusive",
                    )
                )
            # Case C: HTTP 200 returned -> inspect content validity
            elif resp.status_code == 200:
                body = resp.body_text or ""
                has_contact = any(line.strip().lower().startswith("contact:") for line in body.splitlines())
                is_html = "text/html" in content_type or "<html" in body.lower()

                if is_html or not has_contact:
                    findings.append(
                        VulnerabilityFinding(
                            id="VULN-BEST-PRACTICE-INVALID-SECURITY-TXT",
                            title="Invalid RFC 9116 security.txt Format",
                            category="Security Best Practice",
                            severity="Info",
                            confidence="High",
                            affected_url_or_component=sectxt_url,
                            evidence=FindingEvidence(
                                check_type="security_best_practice",
                                observed_data={
                                    "status_code": 200,
                                    "content_type": content_type,
                                    "has_contact_directive": has_contact,
                                    "is_html": is_html,
                                },
                                raw_snippet=(
                                    f"HTTP 200 returned but content violates RFC 9116: "
                                    f"{'HTML page returned instead of text/plain' if is_html else 'Mandatory Contact directive missing'}"
                                ),
                                status_code=200,
                                requested_url=sectxt_url,
                                final_url=resp.final_url,
                                observed_headers={"content-type": content_type},
                                check_result="Confirmed observation",
                                confidence_reason="RFC 9116 requires security.txt to be served as text/plain and must contain at least one valid 'Contact:' directive.",
                                is_inferred=False,
                                response_timestamp=resp.response_timestamp,
                            ),
                            potential_impact="Automated tools and security researchers parsing /.well-known/security.txt cannot extract a valid security contact.",
                            remediation="Ensure /.well-known/security.txt is served as text/plain (UTF-8) and contains required 'Contact:' and 'Expires:' directives.",
                            cwe_id="CWE-1059",
                            cve_id=None,
                            scanner_name=self.scanner_name,
                            scanned_at=ts,
                            references=[
                                "https://www.rfc-editor.org/rfc/rfc9116",
                            ],
                            is_confirmed=True,
                            validation_status="Confirmed Observation",
                        )
                    )
                # If 200 and has_contact and not is_html: Valid security.txt! No vulnerability finding.
        except Exception:
            pass
