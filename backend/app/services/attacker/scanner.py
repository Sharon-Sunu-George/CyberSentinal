"""
Safe, Bounded Web Vulnerability Scanner for CyberQuant Attacker Agent.
Performs conservative, non-destructive checks against authorized targets:
- Security headers
- Cookie security flags
- Transport / HTTPS configuration
- Information disclosure (Server, X-Powered-By)
- Safely exposed metadata (robots.txt, security.txt)
- Known CVE correlation based strictly on empirical version evidence.
"""

import http.client
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
USER_AGENT = "CyberQuant-Security-Auditor/1.0 (+https://cyberquant.ai/scanner-policy)"


class SafeHttpResponse:
    """Encapsulates response data from a safe HTTP probe."""
    def __init__(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        body_text: str,
        remote_ip: str,
        was_https: bool,
    ):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.body_text = body_text
        self.remote_ip = remote_ip
        self.was_https = was_https

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
    ) -> SafeHttpResponse:
        if redirect_depth > MAX_REDIRECT_HOPS:
            raise SSRFProtectionError(f"Exceeded maximum redirect limit ({MAX_REDIRECT_HOPS}).")

        normalized_url, hostname, port, path = normalize_target_url(url)
        current_scheme = "https" if normalized_url.startswith("https://") else "http"

        # Initialize origin scope on initial request (depth 0)
        target_scheme = allowed_origin_scheme or current_scheme
        target_host = allowed_origin_host or hostname
        target_port = allowed_origin_port or port

        # Scope validation on redirects (depth > 0)
        if redirect_depth > 0:
            # 1. Hostname constraint
            if hostname != target_host:
                raise SSRFProtectionError(
                    f"Redirect to host '{hostname}' rejected: escapes authorized target host '{target_host}'."
                )

            # 2. Scheme constraint: HTTPS cannot downgrade to HTTP
            if target_scheme == "https" and current_scheme == "http":
                raise SSRFProtectionError(
                    f"Redirect scheme downgrade from HTTPS to HTTP on '{hostname}' is prohibited."
                )

            # 3. Port constraint: Cannot redirect to arbitrary non-standard service ports
            if port != target_port:
                # Only allow standard web port upgrade (80 -> 443 on HTTPS)
                if not (target_port == 80 and port == 443 and current_scheme == "https"):
                    raise SSRFProtectionError(
                        f"Redirect to port {port} rejected: escapes authorized target port scope {target_port}."
                    )

        # Resolve and pin IP before connecting (DNS rebinding protection)
        verified_ip, family = resolve_and_verify_ip(hostname, port)
        is_https = (current_scheme == "https")

        raw_sock = None
        conn = None

        try:
            # Establish direct socket connection to verified IP
            raw_sock = socket.socket(family, socket.SOCK_STREAM)
            raw_sock.settimeout(self.timeout)
            raw_sock.connect((verified_ip, port))

            if is_https:
                ssl_ctx = ssl.create_default_context()
                # Wrap socket preserving SNI hostname for TLS verification
                sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=hostname)
            else:
                sock = raw_sock

            # Use http.client over established, verified socket
            if is_https:
                conn = http.client.HTTPSConnection(hostname, port=port, timeout=self.timeout)
            else:
                conn = http.client.HTTPConnection(hostname, port=port, timeout=self.timeout)

            conn.sock = sock

            req_headers = {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Host": hostname if (port in (80, 443)) else f"{hostname}:{port}",
                "Connection": "close",
            }

            conn.request(method, path, headers=req_headers)
            response = conn.getresponse()

            # Read bounded body
            body_chunks = []
            bytes_read = 0
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body_chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read > MAX_RESPONSE_BYTES:
                    break

            raw_body = b"".join(body_chunks)
            body_text = raw_body.decode("utf-8", errors="replace")

            # Collect response headers
            headers_dict: Dict[str, str] = {}
            cookie_headers: List[str] = []
            for header_name, header_val in response.getheaders():
                if header_name.lower() == "set-cookie":
                    cookie_headers.append(header_val)
                headers_dict[header_name] = header_val

            if cookie_headers:
                headers_dict["set-cookie"] = "\n".join(cookie_headers)

            status_code = response.status

            # Handle redirects safely
            if status_code in (301, 302, 303, 307, 308):
                location = headers_dict.get("location") or headers_dict.get("Location")
                if location:
                    redirect_url = urllib.parse.urljoin(normalized_url, location)
                    conn.close()
                    conn = None
                    return self.request(
                        redirect_url,
                        method="GET",
                        allowed_origin_scheme=target_scheme,
                        allowed_origin_host=target_host,
                        allowed_origin_port=target_port,
                        redirect_depth=redirect_depth + 1,
                    )

            return SafeHttpResponse(
                url=normalized_url,
                status_code=status_code,
                headers=headers_dict,
                body_text=body_text,
                remote_ip=verified_ip,
                was_https=is_https,
            )

        except (socket.timeout, TimeoutError):
            raise TimeoutError(f"Connection to '{hostname}' timed out after {self.timeout}s.")
        except Exception:
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass


class EvidenceBasedScanner:
    """
    Executes non-destructive evidence-based security auditing.
    Never confirms a vulnerability without observed proof.
    """

    def __init__(self, client: Optional[SafeHttpClient] = None):
        self.client = client or SafeHttpClient()

    def scan(self, target_url: str) -> Tuple[List[VulnerabilityFinding], Dict[str, Any]]:
        normalized_url, hostname, port, path = normalize_target_url(target_url)
        findings: List[VulnerabilityFinding] = []
        scan_meta: Dict[str, Any] = {
            "target_url": target_url,
            "normalized_url": normalized_url,
            "target_host": hostname,
            "target_ip": None,
        }

        # Probe 1: Primary Target Page
        try:
            main_resp = self.client.request(normalized_url, allowed_origin_host=hostname)
            scan_meta["target_ip"] = main_resp.remote_ip
            scan_meta["status_code"] = main_resp.status_code
        except Exception as e:
            scan_meta["error"] = str(e)
            raise

        # Check 1: HTTPS & Transport Security
        self._check_transport_security(main_resp, findings)

        # Check 2: Essential Security Headers
        self._check_security_headers(main_resp, findings)

        # Check 3: Cookie Security Flags
        self._check_cookie_flags(main_resp, findings)

        # Check 4: Information Disclosure (Server & X-Powered-By)
        self._check_information_disclosure(main_resp, findings)

        # Check 5: Safely Exposed Resources (/robots.txt)
        self._check_robots_txt(hostname, port, main_resp.was_https, findings)

        # Check 6: Security.txt Presence
        self._check_security_txt(hostname, port, main_resp.was_https, findings)

        return findings, scan_meta

    def _check_transport_security(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding]):
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
                    ),
                    potential_impact="Network eavesdroppers and man-in-the-middle attackers can intercept or modify transmitted credentials, session cookies, and sensitive payloads.",
                    remediation="Migrate site to HTTPS, redirect all HTTP port 80 traffic to HTTPS port 443, and enable HSTS.",
                    cve_id=None,
                    is_confirmed=True,
                    validation_status="Confirmed Observation",
                )
            )
        else:
            # Check HSTS (Strict-Transport-Security)
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
                            observed_data={"missing_header": "Strict-Transport-Security"},
                            raw_snippet="Response headers do not include 'Strict-Transport-Security'.",
                            status_code=resp.status_code,
                        ),
                        potential_impact="Users connecting over insecure networks can be downgraded to unencrypted HTTP via SSL-stripping attacks on subsequent visits.",
                        remediation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server configuration.",
                        cve_id=None,
                        is_confirmed=True,
                        validation_status="Security Weakness",
                    )
                )

    def _check_security_headers(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding]):
        # Check Content-Security-Policy
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
                        raw_snippet="Response header 'Content-Security-Policy' is absent.",
                        status_code=resp.status_code,
                    ),
                    potential_impact="Increases susceptibility to Cross-Site Scripting (XSS), clickjacking, and unauthorized inline script or data injection.",
                    remediation="Define a restrictive Content Security Policy (e.g., default-src 'self'; script-src 'self'; object-src 'none').",
                    cve_id=None,
                    is_confirmed=True,
                    validation_status="Security Weakness",
                )
            )

        # Check X-Content-Type-Options
        xcto = resp.get_header("X-Content-Type-Options")
        if not xcto or "nosniff" not in xcto.lower():
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
                        observed_data={"header_value": xcto or "absent"},
                        raw_snippet=f"X-Content-Type-Options is {xcto or 'missing'}",
                        status_code=resp.status_code,
                    ),
                    potential_impact="Browsers may MIME-sniff response bodies away from the declared Content-Type, potentially executing non-executable files as JavaScript or HTML.",
                    remediation="Add 'X-Content-Type-Options: nosniff' to web server response headers.",
                    cve_id=None,
                    is_confirmed=True,
                    validation_status="Security Weakness",
                )
            )

        # Check X-Frame-Options & CSP frame-ancestors
        xfo = resp.get_header("X-Frame-Options")
        has_effective_xfo = bool(xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"))

        has_effective_frame_ancestors = False
        if csp:
            for directive in csp.split(";"):
                parts = directive.strip().split()
                if parts and parts[0].lower() == "frame-ancestors":
                    # Must contain effective allowed values (e.g. 'none', 'self', or origins), not '*' or empty
                    if len(parts) > 1 and parts[1].strip() not in ("*", '""', "''"):
                        has_effective_frame_ancestors = True
                    break

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
                    ),
                    potential_impact="Adversary can embed this page inside an invisible iframe on a malicious website to trick users into unintended actions (Clickjacking).",
                    remediation="Configure 'X-Frame-Options: DENY' or 'SAMEORIGIN', or declare CSP 'frame-ancestors 'self''.",
                    cve_id=None,
                    is_confirmed=True,
                    validation_status="Security Weakness",
                )
            )

    def _check_cookie_flags(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding]):
        set_cookie_raw = resp.get_header("set-cookie")
        if not set_cookie_raw:
            return

        cookies = [c.strip() for c in set_cookie_raw.split("\n") if c.strip()]
        for cookie_str in cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            name_val = parts[0]
            cookie_name = name_val.split("=")[0].strip() if "=" in name_val else name_val
            lower_parts = [p.lower() for p in parts[1:]]

            # Check Secure flag
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
                        ),
                        potential_impact="Cookie will be transmitted in cleartext if user ever clicks an HTTP link to the same origin, exposing session tokens.",
                        remediation=f"Append '; Secure' attribute when issuing Set-Cookie for '{cookie_name}'.",
                        cve_id=None,
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )

            # Check HttpOnly flag
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
                        ),
                        potential_impact="Client-side scripts can read this cookie via document.cookie, magnifying the impact of any Cross-Site Scripting (XSS) vulnerability.",
                        remediation=f"Append '; HttpOnly' attribute to '{cookie_name}' if not required by client-side JavaScript.",
                        cve_id=None,
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )

    def _check_information_disclosure(self, resp: SafeHttpResponse, findings: List[VulnerabilityFinding]):
        # Server banner
        server_banner = resp.get_header("Server")
        if server_banner:
            # Check if version numbers are disclosed (e.g. Apache/2.4.49, nginx/1.16.0)
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
                        ),
                        potential_impact=(
                            f"Observed server banner indicates component version mapped to {matched_cve['cve_id']}. "
                            f"If active software is unpatched and lacks backported vendor fixes: {matched_cve['impact']}"
                        ),
                        remediation=matched_cve["remediation"],
                        cve_id=matched_cve["cve_id"],
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
                        ),
                        potential_impact="Revealing exact software and version identifiers enables adversaries to query exploit databases for version-specific exploits.",
                        remediation="Configure web server to suppress granular version banners (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).",
                        cve_id=None,
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )

        # X-Powered-By
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
                        ),
                        potential_impact=(
                            f"Observed runtime banner indicates component version mapped to {matched_cve['cve_id']}. "
                            f"If active software is unpatched and lacks backported vendor fixes: {matched_cve['impact']}"
                        ),
                        remediation=matched_cve["remediation"],
                        cve_id=matched_cve["cve_id"],
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
                        ),
                        potential_impact="Assists attackers in fingerprinting backend frameworks and tailoring exploits to framework vulnerabilities.",
                        remediation="Disable the X-Powered-By header in application server or framework configuration (e.g., app.disable('x-powered-by') in Express).",
                        cve_id=None,
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )

    def _check_robots_txt(self, host: str, port: int, is_https: bool, findings: List[VulnerabilityFinding]):
        scheme = "https" if is_https else "http"
        port_suffix = f":{port}" if (is_https and port != 443) or (not is_https and port != 80) else ""
        robots_url = f"{scheme}://{host}{port_suffix}/robots.txt"

        try:
            resp = self.client.request(robots_url, allowed_origin_host=host)
            if resp.status_code == 200 and resp.body_text:
                # Check for sensitive path keywords in Disallow directives
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
                                check_type="info_disclosure",
                                observed_data={"disallowed_sensitive_paths": disallowed_paths[:5]},
                                raw_snippet=f"Disallowed paths found: {', '.join(disallowed_paths[:5])}",
                                status_code=resp.status_code,
                            ),
                            potential_impact="robots.txt reveals administrative or internal directory structures to search engines and public threat actors.",
                            remediation="Do not rely on robots.txt to hide sensitive endpoints. Implement proper access control and remove sensitive path entries.",
                            cve_id=None,
                            is_confirmed=True,
                            validation_status="Confirmed Observation",
                        )
                    )
        except Exception:
            # Non-blocking probe; continue without error
            pass

    def _check_security_txt(self, host: str, port: int, is_https: bool, findings: List[VulnerabilityFinding]):
        scheme = "https" if is_https else "http"
        port_suffix = f":{port}" if (is_https and port != 443) or (not is_https and port != 80) else ""
        sectxt_url = f"{scheme}://{host}{port_suffix}/.well-known/security.txt"

        try:
            resp = self.client.request(sectxt_url, allowed_origin_host=host)
            if resp.status_code != 200:
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
                            observed_data={"status_code": resp.status_code},
                            raw_snippet=f"GET /.well-known/security.txt returned HTTP {resp.status_code}",
                            status_code=resp.status_code,
                        ),
                        potential_impact="Security researchers discovering vulnerabilities lack an official, cryptographically verified reporting channel (RFC 9116).",
                        remediation="Publish a valid RFC 9116 security.txt file at /.well-known/security.txt with Contact and Expires directives.",
                        cve_id=None,
                        is_confirmed=True,
                        validation_status="Informational Observation",
                    )
                )
        except Exception:
            # Non-blocking probe; continue
            pass
