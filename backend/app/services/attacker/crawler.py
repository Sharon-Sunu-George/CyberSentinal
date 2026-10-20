"""
Browser-rendered, JavaScript-aware full-site crawler for CyberSentinal.
Uses Playwright with Chromium to:
1. Render pages with dynamic JavaScript execution.
2. Intercept and block all non-permitted or SSRF network requests.
3. Discover DOM anchors, same-origin links, and forms (without auto-submitting).
4. Observe browser requests and responses for web perimeter inventory.
5. Recursively crawl same-origin links up to configurable max_pages and max_depth.
6. Provide progress callbacks for live streaming/polling updates.
7. Support clean cancellation and timeout termination.
"""

import asyncio
import datetime
import logging
import urllib.parse
from typing import List, Dict, Any, Optional, Set, Callable, Tuple

from app.schemas.attacker import (
    DiscoveredPage,
    DiscoveredForm,
    DiscoveredRequest,
    VulnerabilityFinding,
    FindingEvidence,
)
from app.services.attacker.ssrf_guard import (
    normalize_target_url,
    validate_destination_url,
    get_local_dev_target_config,
    resolve_and_verify_ip,
    SSRFProtectionError,
)

logger = logging.getLogger("cybersentinel.crawler")


def normalize_crawler_url(raw_url: str, base_url: str) -> Optional[str]:
    """
    Normalizes a candidate link discovered on a page:
    - Resolves relative URLs against base_url
    - Strips fragment identifiers (#section)
    - Strips common trailing slashes for path equivalence
    - Preserves query parameters while avoiding duplication
    - Rejects javascript:, mailto:, tel:, data: schemes
    """
    try:
        joined = urllib.parse.urljoin(base_url, raw_url.strip())
        parsed = urllib.parse.urlsplit(joined)
        scheme = parsed.scheme.lower()

        if scheme not in ("http", "https"):
            return None

        hostname = (parsed.hostname or "").lower().strip(".")
        if not hostname:
            return None

        port = parsed.port or (443 if scheme == "https" else 80)
        port_part = f":{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else ""

        # Normalize path: remove redundant slashes, strip trailing slash if not root
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        # Sort query parameters to avoid permutation explosion
        query = ""
        if parsed.query:
            q_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            # Retain unique keys up to 8 parameters
            sorted_q = sorted(q_pairs[:8], key=lambda x: x[0])
            query = f"?{urllib.parse.urlencode(sorted_q)}"

        normalized = f"{scheme}://{hostname}{port_part}{path}{query}"
        return normalized
    except Exception:
        return None


def is_same_origin(candidate_url: str, target_origin: Any) -> bool:
    """
    Checks if candidate_url strictly belongs to the target origin (scheme, hostname, port).
    Supports either a target origin tuple (scheme, host, port) or a full target URL string.
    """
    try:
        if isinstance(target_origin, str):
            p = urllib.parse.urlsplit(target_origin)
            target_scheme = p.scheme.lower()
            target_host = (p.hostname or "").lower().strip(".")
            target_port = p.port or (443 if target_scheme == "https" else 80)
        else:
            target_scheme, target_host, target_port = target_origin
        parsed = urllib.parse.urlsplit(candidate_url)
        cand_scheme = parsed.scheme.lower()
        cand_host = (parsed.hostname or "").lower().strip(".")
        cand_port = parsed.port or (443 if cand_scheme == "https" else 80)

        return (
            cand_scheme == target_scheme
            and cand_host == target_host
            and cand_port == target_port
        )
    except Exception:
        return False


class PlaywrightCrawler:
    """
    Asynchronous headless browser crawler based on Playwright/Chromium.
    Enforces strict same-origin isolation and real-time request SSRF filtering.
    """

    def __init__(
        self,
        max_pages: int = 15,
        max_depth: int = 2,
        per_page_timeout_ms: int = 12000,
        total_timeout_seconds: int = 90,
    ):
        self.max_pages = max(1, min(max_pages, 50))
        self.max_depth = max(0, min(max_depth, 5))
        self.per_page_timeout_ms = per_page_timeout_ms
        self.total_timeout_seconds = total_timeout_seconds
        self.visited_urls: Set[str] = set()

    async def _extract_forms(self, page: Any, current_url: str) -> List[DiscoveredForm]:
        """Extract form metadata without auto-submitting or sending payloads."""
        try:
            raw_forms = await page.evaluate(
                """() => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.getAttribute('action') || '',
                    method: (f.getAttribute('method') || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input, select, textarea'))
                                    .map(i => i.getAttribute('name') || i.getAttribute('id'))
                                    .filter(Boolean)
                }))"""
            )
            forms: List[DiscoveredForm] = []
            for rf in raw_forms:
                act = rf.get("action", "")
                resolved_act = urllib.parse.urljoin(current_url, act) if act else current_url
                forms.append(
                    DiscoveredForm(
                        action=resolved_act,
                        method=rf.get("method", "GET"),
                        input_names=rf.get("inputs") or rf.get("input_names") or [],
                    )
                )
            return forms
        except Exception:
            return []

    async def crawl(
        self,
        start_url: str,
        scan_id: str,
        is_cancelled: Optional[Callable[[], bool]] = None,
        on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_page_discovered: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Tuple[List[DiscoveredPage], List[VulnerabilityFinding], Dict[str, Any]]:
        """
        Executes asynchronous full-site crawl with Chromium.
        Returns (discovered_pages, passive_findings, crawl_summary).
        """
        from playwright.async_api import async_playwright

        normalized_start, target_host, target_port, _ = normalize_target_url(start_url)
        target_scheme = "https" if normalized_start.startswith("https://") else "http"
        target_origin_tuple = (target_scheme, target_host, target_port)

        discovered_pages: List[DiscoveredPage] = []
        passive_findings: List[VulnerabilityFinding] = []
        findings_seen_ids: Set[str] = set()

        visited_urls: Set[str] = set()
        queued_urls: List[Tuple[str, int, str]] = [(normalized_start, 0, "root")]
        known_urls: Set[str] = {normalized_start}

        total_requests_completed = 0
        start_time = datetime.datetime.now(datetime.timezone.utc)
        start_time_iso = start_time.isoformat()

        def _check_cancelled():
            if is_cancelled and is_cancelled():
                return True
            return False

        def _emit_progress(msg: str, curr_url: Optional[str] = None, curr_depth: int = 0):
            if on_progress:
                elapsed = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
                # Documented formula: progress based on visited vs max_pages ceiling
                pct = min(99, int((len(visited_urls) / self.max_pages) * 100))
                on_progress({
                    "scan_id": scan_id,
                    "status": "running",
                    "pages_discovered": len(known_urls),
                    "pages_visited": len(visited_urls),
                    "requests_completed": total_requests_completed,
                    "current_url": curr_url,
                    "current_depth": curr_depth,
                    "findings_count": len(passive_findings),
                    "progress_percentage": pct,
                    "message": msg,
                    "started_at": start_time_iso,
                    "elapsed_seconds": round(elapsed, 1),
                })

        _emit_progress("Launching headless Chromium security sandbox…", normalized_start, 0)

        playwright = None
        browser = None
        context = None

        try:
            playwright = await async_playwright().start()

            # Resolve and pin target host IP to prevent Chromium DNS rebinding
            pinned_ip, _ = resolve_and_verify_ip(target_host, target_port)

            # Format IP for Chromium host-rules: IPv6 addresses must be enclosed in brackets
            formatted_ip = f"[{pinned_ip}]" if ":" in pinned_ip and not pinned_ip.startswith("[") else pinned_ip

            # Build Chromium network isolation args
            # 1. Map target hostname directly to validated IP (Chromium host-rules)
            # 2. Map all other hostnames to ~NOTFOUND to prevent browser from reaching arbitrary internet destinations
            # 3. Disable WebRTC to prevent STUN/TURN UDP leaks or local network interface enumeration
            chromium_args = [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-sync",
                "--disable-webrtc",
                "--disable-features=WebRtcHideLocalIpsWithMdns,MediaStreamAPI",
                f"--host-rules=MAP {target_host} {formatted_ip}, MAP * ~NOTFOUND",
            ]

            browser = await playwright.chromium.launch(
                headless=True,
                args=chromium_args,
            )

            # Preserve strict TLS certificate validation (ignore_https_errors=False)
            # Block service workers natively at the browser engine level
            context = await browser.new_context(
                ignore_https_errors=False,
                service_workers="block",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSentinal-Crawler/2.0",
                viewport={"width": 1280, "height": 800},
            )

            # Additional script fallback to clean navigator.serviceWorker interface
            try:
                await context.add_init_script("delete window.navigator.serviceWorker;")
            except Exception:
                pass

            # SSRF Network Boundary Routing:
            # Intercept EVERY browser request (scripts, images, iframes, fetches, websockets).
            # Verify destination against strict SSRF policy and same-origin / validated destination rules.
            # Block any request that tries to reach loopback, internal IPs, cloud metadata, or unauthorized ports.
            async def _route_interceptor(route, request):
                req_url = request.url
                is_safe, reason = validate_destination_url(req_url)
                if not is_safe:
                    logger.warning(f"[Crawler SSRF Guard] Blocked request: {req_url} ({reason})")
                    try:
                        await route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return

                # Strict target origin restriction: block any third-party network egress in browser sandbox
                if not is_same_origin(req_url, target_origin_tuple):
                    logger.warning(f"[Crawler Isolation] Blocked cross-origin request: {req_url}")
                    try:
                        await route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return

                try:
                    await route.continue_()
                except Exception:
                    pass

            await context.route("**/*", _route_interceptor)

            # Crawl loop: BFS queue up to max_pages and max_depth
            while queued_urls and len(visited_urls) < self.max_pages:
                if _check_cancelled():
                    _emit_progress("Crawl cancelled by user.", None, 0)
                    break

                # Enforce total timeout
                elapsed = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
                if elapsed >= self.total_timeout_seconds:
                    logger.info(f"Crawler reached total timeout of {self.total_timeout_seconds}s")
                    _emit_progress(f"Crawl reached timeout limit ({self.total_timeout_seconds}s). Finalizing results…")
                    break

                current_url, depth, source = queued_urls.pop(0)
                if current_url in visited_urls:
                    continue

                visited_urls.add(current_url)
                _emit_progress(f"Rendering: {current_url}", current_url, depth)

                page = await context.new_page()
                page_requests: List[DiscoveredRequest] = []

                # Defensive event handlers: close unexpected popups, cancel downloads, and block unauthorized WebSockets
                def _on_popup(popup_page):
                    logger.warning(f"[Crawler Security] Suppressing unexpected popup window: {popup_page.url}")
                    asyncio.create_task(popup_page.close())

                def _on_download(download):
                    logger.warning(f"[Crawler Security] Cancelling unexpected file download: {download.url}")
                    asyncio.create_task(download.cancel())

                def _on_websocket(ws):
                    # Verify WebSocket destination against same origin policy
                    if not is_same_origin(ws.url, target_origin_tuple):
                        logger.warning(f"[Crawler Security] Disallowed cross-origin WebSocket attempted: {ws.url}")
                    else:
                        logger.info(f"[Crawler WebSocket] Monitored target WebSocket: {ws.url}")

                page.on("popup", _on_popup)
                page.on("download", _on_download)
                page.on("websocket", _on_websocket)

                def _on_request(req):
                    nonlocal total_requests_completed
                    total_requests_completed += 1
                    page_requests.append(
                        DiscoveredRequest(
                            url=req.url,
                            method=req.method,
                            resource_type=req.resource_type,
                        )
                    )

                page.on("request", _on_request)

                status_code = None
                content_type = None
                page_title = None
                discovered_links: List[str] = []
                discovered_forms: List[DiscoveredForm] = []

                try:
                    # Navigate with per-page timeout
                    response = await page.goto(
                        current_url,
                        wait_until="domcontentloaded",
                        timeout=self.per_page_timeout_ms,
                    )

                    # Give client-side JS / SPAs a brief moment to render dynamic anchors
                    await asyncio.sleep(0.5)

                    if response:
                        status_code = response.status
                        headers = response.headers
                        content_type = headers.get("content-type")

                        # Passive header inspections on this page
                        self._analyze_page_headers(
                            current_url,
                            status_code,
                            headers,
                            passive_findings,
                            findings_seen_ids,
                        )

                    page_title = await page.title()

                    # Extract rendered links: <a href="...">
                    raw_links = await page.eval_on_selector_all(
                        "a[href]",
                        "elements => elements.map(e => e.getAttribute('href')).filter(Boolean)",
                    )
                    discovered_links.extend(raw_links)

                    # Extract form action URLs and methods without auto-submitting
                    raw_forms = await page.eval_on_selector_all(
                        "form",
                        """elements => elements.map(f => ({
                            action: f.getAttribute('action') || '',
                            method: (f.getAttribute('method') || 'GET').toUpperCase(),
                            input_names: Array.from(f.querySelectorAll('input, select, textarea'))
                                            .map(i => i.getAttribute('name') || i.getAttribute('id'))
                                            .filter(Boolean)
                        }))""",
                    )
                    for rf in raw_forms:
                        act = rf.get("action", "")
                        resolved_act = urllib.parse.urljoin(current_url, act) if act else current_url
                        discovered_forms.append(
                            DiscoveredForm(
                                action=resolved_act,
                                method=rf.get("method", "GET"),
                                input_names=rf.get("input_names", []),
                            )
                        )

                except Exception as e:
                    logger.warning(f"Error rendering {current_url}: {str(e)}")
                    # Continue gracefully so partial progress is preserved
                finally:
                    await page.close()

                # Parse query parameters from current URL
                parsed_cur = urllib.parse.urlsplit(current_url)
                q_names = [k for k, _ in urllib.parse.parse_qsl(parsed_cur.query)]

                disc_page = DiscoveredPage(
                    url=current_url,
                    path=parsed_cur.path or "/",
                    depth=depth,
                    status_code=status_code,
                    content_type=content_type,
                    title=page_title,
                    query_params=q_names,
                    forms=discovered_forms,
                    requests=page_requests[:25],  # Cap logged requests per page
                    discovery_source=source,
                    discovered_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                )
                discovered_pages.append(disc_page)
                if on_page_discovered:
                    on_page_discovered(disc_page.model_dump())

                # If below max_depth, queue newly discovered same-origin links
                if depth < self.max_depth:
                    for raw_link in discovered_links:
                        normalized_link = normalize_crawler_url(raw_link, current_url)
                        if not normalized_link:
                            continue

                        # Must be strictly same origin
                        if not is_same_origin(normalized_link, target_origin_tuple):
                            continue

                        if normalized_link not in known_urls:
                            known_urls.add(normalized_link)
                            queued_urls.append((normalized_link, depth + 1, current_url))

        finally:
            if context:
                try:
                    await context.close()
                except Exception:
                    pass
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
            if playwright:
                try:
                    await playwright.stop()
                except Exception:
                    pass

        # Build final crawl summary
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        crawl_summary = {
            "target_url": start_url,
            "normalized_url": normalized_start,
            "target_host": target_host,
            "target_port": target_port,
            "pages_discovered": len(known_urls),
            "pages_visited": len(visited_urls),
            "requests_completed": total_requests_completed,
            "total_findings": len(passive_findings),
            "scanned_at": now_iso,
            "crawler_engine": "CyberSentinal Chromium / Playwright Headless Crawler",
        }

        return discovered_pages, passive_findings, crawl_summary

    @staticmethod
    def _analyze_page_headers(
        page_url: str,
        status_code: Optional[int],
        headers: Dict[str, str],
        findings: List[VulnerabilityFinding],
        seen_ids: Set[str],
    ):
        """
        Evaluates HTTP response headers on discovered pages using the existing security rules.
        Skips proxy/gateway failure pages (502, 503, 504) to avoid false positives.
        Deduplicates across pages.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Skip gateway/proxy error responses
        if status_code in (502, 503, 504, 520, 521, 522, 524):
            return

        # 1. Missing CSP
        csp = lower_headers.get("content-security-policy")
        if not csp:
            fid = "VULN-SEC-HDR-NO-CSP"
            if fid not in seen_ids:
                seen_ids.add(fid)
                findings.append(
                    VulnerabilityFinding(
                        id=fid,
                        title="Missing Content-Security-Policy (CSP) Header",
                        category="Security Headers",
                        severity="Medium",
                        confidence="High",
                        affected_url_or_component=page_url,
                        evidence=FindingEvidence(
                            check_type="security_headers",
                            observed_data={"missing_header": "Content-Security-Policy"},
                            raw_snippet="Response header 'Content-Security-Policy' is absent from HTTP response.",
                            status_code=status_code,
                            requested_url=page_url,
                            final_url=page_url,
                            observed_headers={},
                            check_result="Potential risk",
                            confidence_reason="Finding is based solely on absence of Content-Security-Policy header in observed page headers.",
                            is_inferred=True,
                            response_timestamp=now,
                        ),
                        potential_impact="Without CSP, the browser will execute any injected inline scripts or load external assets without restriction, amplifying XSS risks.",
                        remediation="Configure a Content-Security-Policy header specifying authorized script-src, style-src, and default-src directives.",
                        cwe_id="CWE-693",
                        cve_id=None,
                        scanner_name="CyberSentinal Crawler",
                        scanned_at=now,
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                        is_confirmed=True,
                        validation_status="Security Weakness",
                    )
                )

        # 2. Missing X-Content-Type-Options: nosniff
        xcto = lower_headers.get("x-content-type-options", "").strip().lower()
        if "nosniff" not in xcto:
            fid = "VULN-SEC-HDR-NO-NOSNIFF"
            if fid not in seen_ids:
                seen_ids.add(fid)
                findings.append(
                    VulnerabilityFinding(
                        id=fid,
                        title="Missing X-Content-Type-Options: nosniff Header",
                        category="Security Headers",
                        severity="Low",
                        confidence="High",
                        affected_url_or_component=page_url,
                        evidence=FindingEvidence(
                            check_type="security_headers",
                            observed_data={"header_value": xcto or "absent"},
                            raw_snippet=f"X-Content-Type-Options is '{xcto or 'absent'}'.",
                            status_code=status_code,
                            requested_url=page_url,
                            final_url=page_url,
                            observed_headers={"x-content-type-options": xcto} if xcto else {},
                            check_result="Confirmed observation" if xcto else "Potential risk",
                            confidence_reason="Direct observation of header value missing mandatory 'nosniff' directive.",
                            is_inferred=False if xcto else True,
                            response_timestamp=now,
                        ),
                        potential_impact="Browsers may MIME-sniff response bodies away from the declared content-type, creating script execution vectors via user uploads.",
                        remediation="Add 'X-Content-Type-Options: nosniff' header to all HTTP responses.",
                        cwe_id="CWE-693",
                        cve_id=None,
                        scanner_name="CyberSentinal Crawler",
                        scanned_at=now,
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                        is_confirmed=True,
                        validation_status="Security Weakness",
                    )
                )

        # 3. Server Version Disclosure
        server_banner = lower_headers.get("server")
        if server_banner and any(char.isdigit() for char in server_banner):
            fid = "VULN-INFO-SERVER-VERSION"
            if fid not in seen_ids:
                seen_ids.add(fid)
                findings.append(
                    VulnerabilityFinding(
                        id=fid,
                        title=f"Web Server Version Disclosed: '{server_banner}'",
                        category="Information Disclosure",
                        severity="Low",
                        confidence="High",
                        affected_url_or_component=page_url,
                        evidence=FindingEvidence(
                            check_type="info_disclosure",
                            observed_data={"server_banner": server_banner},
                            raw_snippet=f"Server: {server_banner}",
                            status_code=status_code,
                            requested_url=page_url,
                            final_url=page_url,
                            observed_headers={"server": server_banner},
                            check_result="Confirmed observation",
                            confidence_reason="Direct empirical observation of Server header containing granular version string.",
                            is_inferred=False,
                            response_timestamp=now,
                        ),
                        potential_impact="Revealing granular software versions helps adversaries query vulnerability databases for targeted exploits.",
                        remediation="Suppress version banners in web server configuration (e.g. server_tokens off in Nginx).",
                        cwe_id="CWE-200",
                        cve_id=None,
                        scanner_name="CyberSentinal Crawler",
                        scanned_at=now,
                        references=["https://owasp.org/www-community/attacks/Fingerprinting"],
                        is_confirmed=True,
                        validation_status="Confirmed Observation",
                    )
                )
