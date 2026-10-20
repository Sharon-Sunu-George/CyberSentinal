"""
Attacker Agent REST Endpoints for CyberSentinal.
Provides:
- POST /api/v1/attacker/scan to trigger evidence-based assessments
- GET /api/v1/attacker/scan/{scan_id} to fetch a persisted scan record
- POST /api/v1/attacker/scan/{scan_id}/cancel to cancel a scan
- POST /api/v1/attacker/scan/{scan_id}/rescan to re-execute a scan on an authorized target
- GET /api/v1/attacker/recent to list recent scan history
- GET /api/v1/attacker/scanner-status to inspect scanner capabilities & OWASP ZAP availability.
"""

import os
import threading
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status
from app.schemas.attacker import (
    AttackerScanRequest,
    AttackerScanResponse,
)
from app.services.attacker import (
    AttackerAgentService,
    SSRFProtectionError,
    TargetAuthorizationError,
)
from app.services.attacker.scanner import probe_owasp_zap_status
from app.services.storage import (
    get_scan_record,
    list_recent_scans,
    update_scan_status,
)

router = APIRouter()

MAX_CONCURRENT_SCANS = 3


class ScanConcurrencyLimiter:
    """
    Manages bounded concurrent scan execution without unbounded queues.
    Rejects incoming requests with HTTP 429 when max concurrent capacity is reached.
    """

    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()
        self._active_count = 0
        self._cancelled_scans = set()

    def try_acquire(self) -> bool:
        acquired = self._semaphore.acquire(blocking=False)
        if acquired:
            with self._lock:
                self._active_count += 1
        return acquired

    def release(self):
        with self._lock:
            if self._active_count > 0:
                self._active_count -= 1
        try:
            self._semaphore.release()
        except ValueError:
            pass

    def mark_cancelled(self, scan_id: str):
        with self._lock:
            self._cancelled_scans.add(scan_id)

    def is_cancelled(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._cancelled_scans

    @property
    def active_scans(self) -> int:
        with self._lock:
            return self._active_count


# Global singleton limiter for outbound security scans
scan_limiter = ScanConcurrencyLimiter(max_concurrent=MAX_CONCURRENT_SCANS)


@router.post(
    "/scan",
    response_model=AttackerScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Initiate Attacker Agent Web Security Assessment",
    description=(
        "Executes a conservative, non-destructive web security assessment against an "
        "explicitly authorized target. Prohibits SSRF, private IP spaces, cloud metadata endpoints, "
        "and produces evidence-grounded findings."
    ),
)
def scan_target(request: AttackerScanRequest) -> AttackerScanResponse:
    """
    Scans an authorized target and returns structured findings and inferred adversarial scenarios.
    """
    if not scan_limiter.try_acquire():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Scan concurrency limit reached ({scan_limiter.max_concurrent} simultaneous scans in progress). "
                "Please wait for existing scans to finish and retry."
            ),
        )

    service = AttackerAgentService()

    try:
        response = service.run_scan(request)
        return response
    except TargetAuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Authorization rejected: {str(e)}",
        )
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target rejected by SSRF guard: {str(e)}",
        )
    except TimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Target probe timed out: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to communicate with target: {str(e)}",
        )
    finally:
        scan_limiter.release()


@router.post(
    "/crawl",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start Asynchronous Full-Site Security Crawl",
    description="Initiates an asynchronous browser-rendered full-site security crawl and immediately returns a scan_id for tracking.",
)
def start_crawl(request: AttackerScanRequest) -> Dict[str, Any]:
    from app.services.attacker.job_manager import scan_job_manager

    try:
        scan_id = scan_job_manager.create_job(request)
        return {
            "scan_id": scan_id,
            "status": "queued",
            "target_url": request.target_url,
            "message": "Full-site security crawl queued successfully.",
        }
    except TargetAuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Authorization rejected: {str(e)}",
        )
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target rejected by SSRF guard: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to queue crawl: {str(e)}",
        )


@router.get(
    "/scan/{scan_id}/progress",
    summary="Get Scan Live Progress",
    description="Returns real-time progress metrics (pages discovered, visited, requests, current URL, elapsed time).",
)
def get_scan_progress(scan_id: str) -> Dict[str, Any]:
    from app.services.attacker.job_manager import scan_job_manager

    progress = scan_job_manager.get_progress(scan_id)
    if not progress:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{scan_id}' not found.",
        )
    return progress.model_dump()


@router.get(
    "/scan/{scan_id}/pages",
    summary="Get Discovered Pages",
    description="Returns all pages and forms discovered by the full-site crawler for the specified scan.",
)
def get_scan_pages(scan_id: str) -> List[Dict[str, Any]]:
    from app.services.attacker.job_manager import scan_job_manager

    return scan_job_manager.get_discovered_pages(scan_id)


@router.get(
    "/scan/{scan_id}",
    response_model=Dict[str, Any],
    summary="Get Persisted Scan Record",
    description="Fetches scan status, summary, empirical findings, and discovered pages for a completed or running scan.",
)
def get_scan(scan_id: str) -> Dict[str, Any]:
    from app.services.attacker.job_manager import scan_job_manager

    record = get_scan_record(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found.",
        )

    # Attach discovered pages
    pages = scan_job_manager.get_discovered_pages(scan_id)
    record["discovered_pages"] = pages
    return record


@router.post(
    "/scan/{scan_id}/cancel",
    summary="Cancel Ongoing Scan",
    description="Cancels a running or queued crawl and marks its status as cancelled.",
)
def cancel_scan(scan_id: str) -> Dict[str, Any]:
    from app.services.attacker.job_manager import scan_job_manager

    record = get_scan_record(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found.",
        )

    scan_limiter.mark_cancelled(scan_id)
    scan_job_manager.cancel_job(scan_id)
    update_scan_status(scan_id, "cancelled")
    return {"scan_id": scan_id, "status": "cancelled", "message": "Scan cancelled successfully."}



@router.post(
    "/scan/{scan_id}/rescan",
    response_model=AttackerScanResponse,
    summary="Rescan Authorized Target",
    description="Re-runs security assessment on previously authorized target to verify remediations.",
)
def rescan_target(scan_id: str) -> AttackerScanResponse:
    record = get_scan_record(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found.",
        )

    # Re-run scan with explicit authorization confirmed
    req = AttackerScanRequest(
        target_url=record["target_url"],
        is_authorized=True,
    )
    return scan_target(req)


@router.get(
    "/recent",
    response_model=List[Dict[str, Any]],
    summary="List Recent Scans",
    description="Returns recent scan execution history.",
)
def list_scans() -> List[Dict[str, Any]]:
    return list_recent_scans(limit=10)


@router.get(
    "/scanner-status",
    summary="Inspect Scanner Capabilities and OWASP ZAP Status",
    description="Reports active scanner engine capabilities, supported checks, OWASP ZAP integration status, and local development scan configuration.",
)
def get_scanner_status() -> Dict[str, Any]:
    from app.services.attacker.ssrf_guard import get_local_dev_target_config, get_internal_network_config
    zap_status = probe_owasp_zap_status()
    local_dev_cfg = get_local_dev_target_config()
    internal_cfg = get_internal_network_config()
    return {
        "engine": "CyberSentinal Evidence-Based Scanner v2.0",
        "active_concurrent_scans": scan_limiter.active_scans,
        "max_concurrent_capacity": scan_limiter.max_concurrent,
        "target_classes": {
            "public": "External internet targets (bounded passive assessment of authorized sites)",
            "local_dev": "Opt-in local development targets with explicit host/port allowlisting",
            "private_network": "Private internal networks (denied by default; administrative allowlist required)",
        },
        "owasp_zap": zap_status,
        "local_dev_scan": {
            "is_enabled": local_dev_cfg is not None,
            "target": local_dev_cfg.get("origin") if local_dev_cfg else None,
            "allowed_host": local_dev_cfg.get("host") if local_dev_cfg else None,
            "allowed_port": local_dev_cfg.get("port") if local_dev_cfg else None,
        },
        "internal_network_scan": {
            "is_enabled": internal_cfg is not None,
            "allowed_cidrs": [str(net) for net in internal_cfg["allowed_networks"]] if internal_cfg else [],
        },
        "supported_checks": [
            "Transport Security (HTTPS/HSTS)",
            "Content-Security-Policy (CSP)",
            "X-Frame-Options / Clickjacking",
            "X-Content-Type-Options (nosniff)",
            "Referrer-Policy",
            "Permissions-Policy",
            "CORS Access-Control Policies",
            "Cookie Attributes (Secure, HttpOnly)",
            "Server Banner Information Disclosure",
            "Robots.txt Sensitive Disallow Directives",
            "RFC 9116 security.txt Contact Directives",
            "Public Sensitive File Exposure (/.env, /.git/HEAD)",
            "Suspicious Redirects & Transport Downgrade",
            "Curated CVE Version Fingerprint Matching",
            "Website Trust & Threat Intelligence (Google Safe Browsing, PhishTank)",
            "Domain Lookalike, Typosquatting & Punycode Impersonation Detection",
            "Canonical URL Deduplication & Verification",
        ],
        "threat_intel_providers": {
            "google_safe_browsing": bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")),
            "phishtank": bool(os.getenv("PHISHTANK_API_KEY")),
        },
    }
