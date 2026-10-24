"""
Persistent Storage Service for CyberSentinal.
Uses SQLite for persistent, reliable, zero-dependency storage of:
- Scans and scan execution states (queued, running, completed, failed, cancelled)
- Security findings with evidence, CWE/CVE mappings, and verification status
- Remediation statuses (Open, Planned, In Progress, Fixed, Accepted Risk, Verified)
- Budget-aware remediation allocation plans.
"""

import json
import os
import sqlite3
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_PATH_ENV = os.getenv("DATABASE_PATH")
DB_FILE = Path(DB_PATH_ENV).resolve() if DB_PATH_ENV else Path(__file__).resolve().parent.parent.parent / "cybersentinel.db"


def get_db_connection() -> sqlite3.Connection:
    if not DB_FILE.parent.exists():
        DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    target_ip TEXT,
                    scope_limitations TEXT,
                    scanner_info_json TEXT,
                    summary_json TEXT,
                    inferred_scenarios_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    affected_url_or_component TEXT NOT NULL,
                    cwe_id TEXT,
                    cve_id TEXT,
                    evidence_json TEXT NOT NULL,
                    potential_impact TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    scanner_name TEXT NOT NULL,
                    scanned_at TEXT,
                    references_json TEXT,
                    is_confirmed INTEGER NOT NULL,
                    validation_status TEXT NOT NULL,
                    remediation_status TEXT DEFAULT 'Open',
                    remediation_notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_plans (
                    plan_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    available_budget REAL NOT NULL,
                    hourly_rate REAL NOT NULL,
                    total_cost REAL NOT NULL,
                    proposed_spending REAL NOT NULL,
                    remaining_budget REAL NOT NULL,
                    budget_shortfall REAL NOT NULL,
                    baseline_risk_score REAL NOT NULL,
                    projected_residual_risk REAL NOT NULL,
                    total_risk_reduction_percent REAL NOT NULL,
                    risk_reduction_per_dollar REAL NOT NULL,
                    fix_immediately_json TEXT NOT NULL,
                    fix_next_json TEXT NOT NULL,
                    defer_or_mitigate_json TEXT NOT NULL,
                    unbudgeted_high_risk_json TEXT NOT NULL,
                    scoring_notes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS discovered_pages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    path TEXT NOT NULL,
                    depth INTEGER NOT NULL DEFAULT 0,
                    status_code INTEGER,
                    content_type TEXT,
                    title TEXT,
                    query_params_json TEXT,
                    forms_json TEXT,
                    requests_json TEXT,
                    discovery_source TEXT,
                    discovered_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    old_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    evidence_json TEXT,
                    notes TEXT,
                    changed_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
                """
            )
            # Add verification_evidence_json column if missing in findings table
            try:
                conn.execute("ALTER TABLE findings ADD COLUMN verification_evidence_json TEXT")
            except Exception:
                pass  # already exists

            # Add trust_assessment_json column if missing in scans table
            try:
                conn.execute("ALTER TABLE scans ADD COLUMN trust_assessment_json TEXT")
            except Exception:
                pass  # already exists

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_plans_scan_id ON remediation_plans(scan_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pages_scan_id ON discovered_pages(scan_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rem_history ON remediation_history(scan_id, finding_id)"
            )

            # Reliability & restart resilience: Mark any stranded in-progress or queued scans as failed
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            conn.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    scope_limitations = scope_limitations || ' [Server process restarted while scan was active]',
                    updated_at = ?
                WHERE status IN ('running', 'queued')
                """,
                (now_iso,),
            )
    finally:
        conn.close()


# Initialize database upon import
init_db()


def save_scan_record(scan_data: Dict[str, Any]) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, target_url, normalized_url, scanned_at, status,
                    target_ip, scope_limitations, scanner_info_json,
                    summary_json, inferred_scenarios_json, trust_assessment_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    status=excluded.status,
                    target_ip=excluded.target_ip,
                    summary_json=excluded.summary_json,
                    inferred_scenarios_json=excluded.inferred_scenarios_json,
                    trust_assessment_json=COALESCE(excluded.trust_assessment_json, scans.trust_assessment_json),
                    updated_at=excluded.updated_at
                """,
                (
                    scan_data["scan_id"],
                    scan_data["target_url"],
                    scan_data["normalized_url"],
                    scan_data.get("scanned_at", now),
                    scan_data.get("status", "completed"),
                    scan_data.get("target_ip"),
                    scan_data.get("scope_limitations", ""),
                    json.dumps(scan_data.get("scanner_info", {})),
                    json.dumps(scan_data.get("summary", {})),
                    json.dumps(scan_data.get("inferred_attack_scenarios", [])),
                    json.dumps(scan_data.get("trust_assessment")) if scan_data.get("trust_assessment") is not None else None,
                    now,
                    now,
                ),
            )

            # Insert findings if provided
            findings = scan_data.get("findings", [])
            for f in findings:
                # Check if finding already saved for this scan
                existing = conn.execute(
                    "SELECT id FROM findings WHERE scan_id = ? AND finding_id = ?",
                    (scan_data["scan_id"], f["id"]),
                ).fetchone()

                if not existing:
                    conn.execute(
                        """
                        INSERT INTO findings (
                            scan_id, finding_id, title, category, severity, confidence,
                            affected_url_or_component, cwe_id, cve_id, evidence_json,
                            potential_impact, remediation, scanner_name, scanned_at,
                            references_json, is_confirmed, validation_status,
                            remediation_status, remediation_notes, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_data["scan_id"],
                            f["id"],
                            f["title"],
                            f["category"],
                            f["severity"],
                            f["confidence"],
                            f["affected_url_or_component"],
                            f.get("cwe_id"),
                            f.get("cve_id"),
                            json.dumps(f.get("evidence", {})),
                            f["potential_impact"],
                            f["remediation"],
                            f.get("scanner_name", "CyberSentinel Evidence-Based Scanner"),
                            f.get("scanned_at", scan_data.get("scanned_at", now)),
                            json.dumps(f.get("references", [])),
                            1 if f.get("is_confirmed", True) else 0,
                            f.get("validation_status", "Confirmed Observation"),
                            f.get("remediation_status") or "Open",
                            f.get("remediation_notes", ""),
                            now,
                            now,
                        ),
                    )
                else:
                    # Update evidence while preserving user remediation lifecycle status
                    conn.execute(
                        """
                        UPDATE findings SET
                            evidence_json = ?,
                            validation_status = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            json.dumps(f.get("evidence", {})),
                            f.get("validation_status", "Confirmed Observation"),
                            now,
                            existing["id"],
                        ),
                    )
    finally:
        conn.close()


def update_scan_status(scan_id: str, status: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "UPDATE scans SET status = ?, updated_at = ? WHERE scan_id = ?",
                (status, now, scan_id),
            )
    finally:
        conn.close()


def get_scan_record(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None

        findings_rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,)
        ).fetchall()

        findings = []
        for fr in findings_rows:
            findings.append({
                "id": fr["finding_id"],
                "title": fr["title"],
                "category": fr["category"],
                "severity": fr["severity"],
                "confidence": fr["confidence"],
                "affected_url_or_component": fr["affected_url_or_component"],
                "cwe_id": fr["cwe_id"],
                "cve_id": fr["cve_id"],
                "evidence": json.loads(fr["evidence_json"] or "{}"),
                "potential_impact": fr["potential_impact"],
                "remediation": fr["remediation"],
                "scanner_name": fr["scanner_name"],
                "scanned_at": fr["scanned_at"],
                "references": json.loads(fr["references_json"] or "[]"),
                "is_confirmed": bool(fr["is_confirmed"]),
                "validation_status": fr["validation_status"],
                "remediation_status": fr["remediation_status"],
                "remediation_notes": fr["remediation_notes"],
                "verification_evidence": json.loads(fr["verification_evidence_json"] or "{}") if "verification_evidence_json" in fr.keys() and fr["verification_evidence_json"] else None,
            })

        return {
            "scan_id": row["scan_id"],
            "target_url": row["target_url"],
            "normalized_url": row["normalized_url"],
            "scanned_at": row["scanned_at"],
            "status": row["status"],
            "target_ip": row["target_ip"],
            "scope_limitations": row["scope_limitations"],
            "scanner_info": json.loads(row["scanner_info_json"] or "{}"),
            "summary": json.loads(row["summary_json"] or "{}"),
            "findings": findings,
            "inferred_attack_scenarios": json.loads(row["inferred_scenarios_json"] or "[]"),
            "trust_assessment": json.loads(row["trust_assessment_json"] or "null") if "trust_assessment_json" in row.keys() and row["trust_assessment_json"] else None,
        }
    finally:
        conn.close()


def list_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT scan_id, target_url, normalized_url, scanned_at, status, target_ip, summary_json, trust_assessment_json, created_at FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        results = []
        for r in rows:
            results.append({
                "scan_id": r["scan_id"],
                "target_url": r["target_url"],
                "normalized_url": r["normalized_url"],
                "scanned_at": r["scanned_at"],
                "status": r["status"],
                "target_ip": r["target_ip"],
                "summary": json.loads(r["summary_json"] or "{}"),
                "trust_assessment": json.loads(r["trust_assessment_json"] or "null") if "trust_assessment_json" in r.keys() and r["trust_assessment_json"] else None,
                "created_at": r["created_at"],
            })
        return results
    finally:
        conn.close()


def save_discovered_page(scan_id: str, page_data: Dict[str, Any]) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO discovered_pages (
                    scan_id, url, path, depth, status_code, content_type,
                    title, query_params_json, forms_json, requests_json,
                    discovery_source, discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    page_data["url"],
                    page_data.get("path", "/"),
                    page_data.get("depth", 0),
                    page_data.get("status_code"),
                    page_data.get("content_type"),
                    page_data.get("title"),
                    json.dumps(page_data.get("query_params", [])),
                    json.dumps(page_data.get("forms", [])),
                    json.dumps(page_data.get("requests", [])),
                    page_data.get("discovery_source", "crawler"),
                    page_data.get("discovered_at") or now,
                ),
            )
    finally:
        conn.close()


def get_discovered_pages(scan_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM discovered_pages WHERE scan_id = ? ORDER BY id ASC",
            (scan_id,),
        ).fetchall()
        pages = []
        for r in rows:
            pages.append({
                "url": r["url"],
                "path": r["path"],
                "depth": r["depth"],
                "status_code": r["status_code"],
                "content_type": r["content_type"],
                "title": r["title"],
                "query_params": json.loads(r["query_params_json"] or "[]"),
                "forms": json.loads(r["forms_json"] or "[]"),
                "requests": json.loads(r["requests_json"] or "[]"),
                "discovery_source": r["discovery_source"],
                "discovered_at": r["discovered_at"],
            })
        return pages
    finally:
        conn.close()



def update_finding_remediation_status(
    scan_id: str,
    finding_id: str,
    status: str,
    notes: Optional[str] = None,
    verification_evidence: Optional[Dict[str, Any]] = None,
) -> bool:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            # Query existing status for history logging
            old_row = conn.execute(
                "SELECT remediation_status FROM findings WHERE scan_id = ? AND finding_id = ?",
                (scan_id, finding_id),
            ).fetchone()
            old_status = old_row["remediation_status"] if old_row else "Not Started"

            evidence_str = json.dumps(verification_evidence) if verification_evidence is not None else None

            if notes is not None and evidence_str is not None:
                cur = conn.execute(
                    """
                    UPDATE findings
                    SET remediation_status = ?, remediation_notes = ?, verification_evidence_json = ?, updated_at = ?
                    WHERE scan_id = ? AND finding_id = ?
                    """,
                    (status, notes, evidence_str, now, scan_id, finding_id),
                )
            elif notes is not None:
                cur = conn.execute(
                    """
                    UPDATE findings
                    SET remediation_status = ?, remediation_notes = ?, updated_at = ?
                    WHERE scan_id = ? AND finding_id = ?
                    """,
                    (status, notes, now, scan_id, finding_id),
                )
            elif evidence_str is not None:
                cur = conn.execute(
                    """
                    UPDATE findings
                    SET remediation_status = ?, verification_evidence_json = ?, updated_at = ?
                    WHERE scan_id = ? AND finding_id = ?
                    """,
                    (status, evidence_str, now, scan_id, finding_id),
                )
            else:
                cur = conn.execute(
                    """
                    UPDATE findings
                    SET remediation_status = ?, updated_at = ?
                    WHERE scan_id = ? AND finding_id = ?
                    """,
                    (status, now, scan_id, finding_id),
                )

            # Record in remediation history audit log
            if cur.rowcount > 0:
                conn.execute(
                    """
                    INSERT INTO remediation_history (
                        scan_id, finding_id, old_status, new_status, evidence_json, notes, changed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, finding_id, old_status, status, evidence_str, notes or "", now),
                )

            return cur.rowcount > 0
    finally:
        conn.close()


def get_remediation_history(scan_id: str, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        if finding_id:
            rows = conn.execute(
                "SELECT * FROM remediation_history WHERE scan_id = ? AND finding_id = ? ORDER BY id DESC",
                (scan_id, finding_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM remediation_history WHERE scan_id = ? ORDER BY id DESC",
                (scan_id,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "scan_id": r["scan_id"],
                "finding_id": r["finding_id"],
                "old_status": r["old_status"],
                "new_status": r["new_status"],
                "evidence": json.loads(r["evidence_json"] or "{}") if r["evidence_json"] else None,
                "notes": r["notes"],
                "changed_at": r["changed_at"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def save_remediation_plan(plan_data: Dict[str, Any]) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO remediation_plans (
                    plan_id, scan_id, available_budget, hourly_rate, total_cost,
                    proposed_spending, remaining_budget, budget_shortfall,
                    baseline_risk_score, projected_residual_risk,
                    total_risk_reduction_percent, risk_reduction_per_dollar,
                    fix_immediately_json, fix_next_json, defer_or_mitigate_json,
                    unbudgeted_high_risk_json, scoring_notes_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(plan_id) DO UPDATE SET
                    available_budget=excluded.available_budget,
                    hourly_rate=excluded.hourly_rate,
                    total_cost=excluded.total_cost,
                    proposed_spending=excluded.proposed_spending,
                    remaining_budget=excluded.remaining_budget,
                    budget_shortfall=excluded.budget_shortfall,
                    baseline_risk_score=excluded.baseline_risk_score,
                    projected_residual_risk=excluded.projected_residual_risk,
                    total_risk_reduction_percent=excluded.total_risk_reduction_percent,
                    risk_reduction_per_dollar=excluded.risk_reduction_per_dollar,
                    fix_immediately_json=excluded.fix_immediately_json,
                    fix_next_json=excluded.fix_next_json,
                    defer_or_mitigate_json=excluded.defer_or_mitigate_json,
                    unbudgeted_high_risk_json=excluded.unbudgeted_high_risk_json,
                    scoring_notes_json=excluded.scoring_notes_json,
                    updated_at=excluded.updated_at
                """,
                (
                    plan_data["plan_id"],
                    plan_data["scan_id"],
                    plan_data["available_budget"],
                    plan_data["hourly_rate"],
                    plan_data["total_cost"],
                    plan_data["proposed_spending"],
                    plan_data["remaining_budget"],
                    plan_data["budget_shortfall"],
                    plan_data["baseline_risk_score"],
                    plan_data["projected_residual_risk"],
                    plan_data["total_risk_reduction_percent"],
                    plan_data["risk_reduction_per_dollar"],
                    json.dumps(plan_data["fix_immediately"]),
                    json.dumps(plan_data["fix_next"]),
                    json.dumps(plan_data["defer_or_mitigate"]),
                    json.dumps(plan_data.get("unbudgeted_high_risk_findings", [])),
                    json.dumps(plan_data.get("scoring_model_notes", [])),
                    now,
                    now,
                ),
            )
    finally:
        conn.close()


def get_latest_remediation_plan(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT * FROM remediation_plans WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1",
            (scan_id,),
        ).fetchone()
        if not row:
            return None

        # Fetch current remediation statuses and verification evidence from findings
        findings_rows = conn.execute(
            "SELECT finding_id, remediation_status, remediation_notes, verification_evidence_json FROM findings WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        status_map = {
            fr["finding_id"]: {
                "status": fr["remediation_status"],
                "notes": fr["remediation_notes"],
                "evidence": json.loads(fr["verification_evidence_json"] or "{}") if "verification_evidence_json" in fr.keys() and fr["verification_evidence_json"] else None
            }
            for fr in findings_rows
        }

        fix_imm = json.loads(row["fix_immediately_json"] or "[]")
        fix_nxt = json.loads(row["fix_next_json"] or "[]")
        defer = json.loads(row["defer_or_mitigate_json"] or "[]")
        unbudgeted = json.loads(row["unbudgeted_high_risk_json"] or "[]")

        # Overlay updated statuses and evidence
        for item in fix_imm + fix_nxt + defer + unbudgeted:
            f_id = item.get("finding_id")
            if f_id in status_map:
                item["status"] = status_map[f_id]["status"]
                item["remediation_status"] = status_map[f_id]["status"]
                if status_map[f_id]["notes"]:
                    item["status_notes"] = status_map[f_id]["notes"]
                if status_map[f_id]["evidence"]:
                    item["verification_evidence"] = status_map[f_id]["evidence"]

        return {
            "plan_id": row["plan_id"],
            "scan_id": row["scan_id"],
            "available_budget": row["available_budget"],
            "hourly_rate": row["hourly_rate"],
            "total_cost": row["total_cost"],
            "proposed_spending": row["proposed_spending"],
            "remaining_budget": row["remaining_budget"],
            "budget_shortfall": row["budget_shortfall"],
            "baseline_risk_score": row["baseline_risk_score"],
            "projected_residual_risk": row["projected_residual_risk"],
            "total_risk_reduction_percent": row["total_risk_reduction_percent"],
            "risk_reduction_per_dollar": row["risk_reduction_per_dollar"],
            "fix_immediately": fix_imm,
            "fix_next": fix_nxt,
            "defer_or_mitigate": defer,
            "unbudgeted_high_risk_findings": unbudgeted,
            "scoring_model_notes": json.loads(row["scoring_notes_json"] or "[]"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    finally:
        conn.close()
