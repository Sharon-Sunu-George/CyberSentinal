"""
Attacker Agent REST Endpoint for CyberQuant.
Provides POST /api/v1/attacker/scan to trigger evidence-based assessments
against authorized targets with comprehensive SSRF protection and error boundaries.
"""

import threading
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

router = APIRouter()

MAX_CONCURRENT_SCANS = 3


class ScanConcurrencyLimiter:
    """
    Manages bounded concurrent scan execution without unbounded queues.
    Rejects incoming requests with HTTP 429 when max concurrent capacity is reached.
    """

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_SCans if "MAX_CONCURRENT_SCans" in locals() else 3):
        self.max_concurrent = max_concurrent
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()
        self._active_count = 0

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
