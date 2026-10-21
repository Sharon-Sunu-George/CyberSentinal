"""
Bounded In-Process Asynchronous Scan Job Manager for CyberSentinal.
Manages crawl and scan tasks lifecycle:
- queued -> running -> completed / failed / cancelled
- Tracks real-time scan progress (pages, visited, requests, current URL, elapsed time)
- Enforces max concurrent tasks (MAX_CONCURRENT_JOBS = 3)
- Stores task status, discoveries, and final outputs in SQLite storage
- Emits real-time progress for client polling and status retrieval
"""

import asyncio
import datetime
import logging
import threading
import uuid
from typing import Dict, Any, Optional, List, Callable

from app.schemas.attacker import (
    AttackerScanRequest,
    AttackerScanResponse,
    AttackerScanSummary,
    ScanProgressUpdate,
    DiscoveredPage,
    VulnerabilityFinding,
)
from app.services.attacker.agent import AttackerAgentService
from app.services.attacker.crawler import PlaywrightCrawler
from app.services.attacker.scanner import EvidenceBasedScanner, SafeHttpClient, deduplicate_findings
from app.services.attacker.ssrf_guard import (
    normalize_target_url,
    TargetAuthorizationError,
    SSRFProtectionError,
)
from app.services.storage import (
    save_scan_record,
    get_scan_record,
    update_scan_status,
    save_discovered_page,
    get_discovered_pages,
)

logger = logging.getLogger("cybersentinel.job_manager")

MAX_CONCURRENT_JOBS = 3


class ScanJob:
    """Represents an active or completed in-process scan job."""

    def __init__(self, scan_id: str, request: AttackerScanRequest):
        self.scan_id = scan_id
        self.request = request
        self.status = "queued"
        self.created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self.cancelled = False
        self.error: Optional[str] = None
        self.progress_data: Dict[str, Any] = {
            "scan_id": scan_id,
            "status": "queued",
            "pages_discovered": 0,
            "pages_visited": 0,
            "requests_completed": 0,
            "current_url": None,
            "current_depth": 0,
            "findings_count": 0,
            "progress_percentage": 0,
            "message": "Queued for execution…",
            "started_at": None,
            "elapsed_seconds": 0.0,
            "completed_at": None,
            "error": None,
        }
        self.discovered_pages: List[Dict[str, Any]] = []
        self.task: Optional[asyncio.Task] = None


class ScanJobManager:
    """
    Singleton in-process job manager coordinating asynchronous crawler jobs.
    Bounded capacity prevents unbounded worker thread accumulation.
    """

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_JOBS):
        self.max_concurrent = max_concurrent
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._active_count = 0

    def create_job(self, request: AttackerScanRequest, scan_id: Optional[str] = None) -> str:
        """
        Validates target parameters and registers a new queued scan job.
        Returns scan_id promptly.
        """
        if not request.is_authorized:
            raise TargetAuthorizationError("Explicit user authorization confirmation is required.")

        # Normalize target URL immediately to validate SSRF boundaries
        normalized_url, hostname, port, path = normalize_target_url(request.target_url)

        job_id = scan_id or f"scan-{uuid.uuid4().hex[:10]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        job = ScanJob(job_id, request)

        with self._lock:
            self._jobs[job_id] = job

        # Persist queued scan in SQLite
        save_scan_record({
            "scan_id": job_id,
            "target_url": request.target_url,
            "normalized_url": normalized_url,
            "scanned_at": now_iso,
            "status": "queued",
            "scope_limitations": "Full-site asynchronous crawl queued.",
            "scanner_info": {"engine": "CyberSentinal Async Playwright Crawler"},
            "summary": {
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "confirmed_count": 0,
                "pages_discovered": 1,
                "pages_visited": 0,
                "requests_completed": 0,
            },
        })

        # Launch background executor task
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            asyncio.create_task(self._run_job_async(job_id))
        else:
            threading.Thread(target=lambda: asyncio.run(self._run_job_async(job_id)), daemon=True).start()

        return job_id

    def cancel_job(self, scan_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(scan_id)
            if not job:
                # Still record in SQLite if exists
                update_scan_status(scan_id, "cancelled")
                return True

            job.cancelled = True
            job.status = "cancelled"
            job.progress_data["status"] = "cancelled"
            job.progress_data["message"] = "Scan cancelled by user."
            job.progress_data["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        update_scan_status(scan_id, "cancelled")
        return True

    def get_progress(self, scan_id: str) -> Optional[ScanProgressUpdate]:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job:
                return ScanProgressUpdate(**job.progress_data)

        # Fallback to SQLite persistence
        record = get_scan_record(scan_id)
        if not record:
            return None

        summary = record.get("summary", {})
        return ScanProgressUpdate(
            scan_id=scan_id,
            status=record.get("status", "completed"),
            pages_discovered=summary.get("pages_discovered", 1),
            pages_visited=summary.get("pages_visited", 1),
            requests_completed=summary.get("requests_completed", 1),
            findings_count=len(record.get("findings", [])),
            progress_percentage=100 if record.get("status") in ("completed", "failed", "cancelled") else 50,
            message=f"Status: {record.get('status')}",
            started_at=record.get("scanned_at"),
            completed_at=record.get("scanned_at") if record.get("status") in ("completed", "failed", "cancelled") else None,
        )

    def record_discovered_page(self, scan_id: str, page_data: Any):
        """Records a discovered page into the active job and SQLite storage."""
        if hasattr(page_data, "model_dump"):
            p_dict = page_data.model_dump()
        elif isinstance(page_data, dict):
            p_dict = page_data
        else:
            p_dict = dict(page_data)

        with self._lock:
            job = self._jobs.get(scan_id)
            if job:
                job.discovered_pages.append(p_dict)
        save_discovered_page(scan_id, p_dict)

    def get_discovered_pages(self, scan_id: str) -> List[Dict[str, Any]]:
        # Check in-memory job first
        with self._lock:
            job = self._jobs.get(scan_id)
            if job and job.discovered_pages:
                return list(job.discovered_pages)

        # Fallback to SQLite
        return get_discovered_pages(scan_id)

    def is_job_cancelled(self, scan_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(scan_id)
            return job.cancelled if job else False

    async def _run_job_async(self, scan_id: str):
        """Worker executing crawl + passive assessment + finding correlation."""
        # Wait for semaphore slot to avoid unbound concurrency
        while not self._semaphore.acquire(blocking=False):
            if self.is_job_cancelled(scan_id):
                return
            await asyncio.sleep(0.5)

        with self._lock:
            self._active_count += 1
            job = self._jobs.get(scan_id)

        if not job or job.cancelled:
            self._semaphore.release()
            with self._lock:
                self._active_count = max(0, self._active_count - 1)
            return

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        job.status = "running"
        job.started_at = now_iso
        job.progress_data["status"] = "running"
        job.progress_data["started_at"] = now_iso
        update_scan_status(scan_id, "running")

        try:
            crawler = PlaywrightCrawler(
                max_pages=job.request.max_pages or 15,
                max_depth=job.request.max_depth or 2,
                total_timeout_seconds=job.request.timeout_seconds or 90,
            )

            def _on_progress(prog: Dict[str, Any]):
                with self._lock:
                    if not job.cancelled:
                        job.progress_data.update(prog)

            def _on_page_disc(page_dict: Dict[str, Any]):
                with self._lock:
                    job.discovered_pages.append(page_dict)
                save_discovered_page(scan_id, page_dict)

            # Step 1: Run Chromium Crawl
            discovered_pages, crawl_findings, crawl_summary = await crawler.crawl(
                start_url=job.request.target_url,
                scan_id=scan_id,
                is_cancelled=lambda: self.is_job_cancelled(scan_id),
                on_progress=_on_progress,
                on_page_discovered=_on_page_disc,
            )

            if self.is_job_cancelled(scan_id):
                update_scan_status(scan_id, "cancelled")
                return

            # Step 2: Also run baseline socket/transport checks on the origin
            agent_service = AttackerAgentService()
            try:
                base_findings, base_meta = agent_service.scanner.scan(job.request.target_url)
            except Exception as e:
                logger.warning(f"Baseline socket checks failed: {str(e)}")
                base_findings, base_meta = [], {}

            # Step 3: Combine and deduplicate findings across crawl and socket probes
            all_findings = deduplicate_findings(crawl_findings + base_findings)

            summary = agent_service._compute_summary(all_findings)
            summary.pages_discovered = crawl_summary["pages_discovered"]
            summary.pages_visited = crawl_summary["pages_visited"]
            summary.requests_completed = crawl_summary["requests_completed"]

            # Derive attack paths
            inferred_scenarios = agent_service._derive_inferred_attack_scenarios(
                all_findings, crawl_summary["normalized_url"]
            )
            defender_handover = agent_service._build_defender_handover(
                all_findings, crawl_summary["normalized_url"], summary
            )

            # Evaluate Website Trust, Scam, Phishing, and Impersonation
            from app.services.attacker.trust_engine import WebsiteTrustService
            trust_service = WebsiteTrustService()

            # Gather page title and forms from crawled pages for impersonation detection
            page_title = None
            all_forms: List[Dict[str, Any]] = []
            for p in discovered_pages:
                if not page_title and p.title:
                    page_title = p.title
                if p.forms:
                    for f in p.forms:
                        if hasattr(f, "model_dump"):
                            all_forms.append(f.model_dump())
                        elif isinstance(f, dict):
                            all_forms.append(f)

            trust_assessment = trust_service.evaluate_trust(
                target_url=crawl_summary["normalized_url"],
                current_scan_id=scan_id,
                final_url=crawl_summary.get("final_url"),
                page_title=page_title,
                forms=all_forms,
            )

            # Persist completed scan record
            completed_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            target_unreachable = bool(base_meta.get("target_unreachable")) or any(f.id == "VULN-SCAN-CONNECTION-FAILED" for f in all_findings)
            is_inconclusive = bool(base_meta.get("is_inconclusive")) or target_unreachable
            
            scope_desc = (
                f"Target host '{job.request.target_url}' could not be reached (connection timed out or host is offline). Safe passive probes could not observe live HTTP responses."
                if target_unreachable
                else (
                    f"Full-site crawler visited {len(discovered_pages)} pages up to depth "
                    f"{job.request.max_depth or 2}. Safe passive checks only."
                )
            )

            save_scan_record({
                "scan_id": scan_id,
                "target_url": job.request.target_url,
                "normalized_url": crawl_summary["normalized_url"],
                "scanned_at": completed_iso,
                "status": "completed",
                "is_inconclusive": is_inconclusive,
                "target_unreachable": target_unreachable,
                "target_ip": base_meta.get("target_ip"),
                "scope_limitations": scope_desc,
                "scanner_info": {
                    "engine": "CyberSentinal Chromium / Playwright Headless Crawler",
                    "crawler_summary": crawl_summary,
                },
                "summary": summary.model_dump(),
                "findings": [f.model_dump() for f in all_findings],
                "inferred_attack_scenarios": [s.model_dump() for s in inferred_scenarios],
                "trust_assessment": trust_assessment.model_dump(),
            })

            with self._lock:
                job.status = "completed"
                job.completed_at = completed_iso
                job.progress_data.update({
                    "status": "completed",
                    "progress_percentage": 100,
                    "pages_discovered": crawl_summary["pages_discovered"],
                    "pages_visited": crawl_summary["pages_visited"],
                    "requests_completed": crawl_summary["requests_completed"],
                    "findings_count": len(all_findings),
                    "message": f"Crawl completed. {len(discovered_pages)} pages indexed, {len(all_findings)} security observations identified.",
                    "completed_at": completed_iso,
                })

        except Exception as e:
            logger.error(f"Scan job {scan_id} failed: {str(e)}", exc_info=True)
            failed_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            update_scan_status(scan_id, "failed")
            with self._lock:
                job.status = "failed"
                job.error = str(e)
                job.completed_at = failed_iso
                job.progress_data.update({
                    "status": "failed",
                    "error": str(e),
                    "message": f"Assessment failed: {str(e)}",
                    "completed_at": failed_iso,
                })
        finally:
            self._semaphore.release()
            with self._lock:
                self._active_count = max(0, self._active_count - 1)


# Global singleton instance
scan_job_manager = ScanJobManager(max_concurrent=MAX_CONCURRENT_JOBS)
