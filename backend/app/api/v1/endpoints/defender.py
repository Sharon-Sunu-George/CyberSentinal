import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status
from app.schemas.defender import (
    DefenderAnalysisRequest,
    DefenderAnalysisResponse,
    RemediationStatusUpdateRequest,
    VerifyRemediationRequest,
    VerifyRemediationResponse,
)
from app.services.defender.engine import DefenderPrioritizationEngine
from app.services.storage import (
    get_latest_remediation_plan,
    update_finding_remediation_status,
    get_scan_record,
    get_remediation_history,
)
from app.services.attacker.scanner import SafeHttpClient, normalize_target_url

router = APIRouter()

# Primary 5-stage lifecycle matching requirements, plus backward-compatible legacy terms
VALID_REMEDIATION_STATUSES = {
    "Not Started",
    "In Progress",
    "Fixed Pending Verification",
    "Verified Fixed",
    "Reopened",
    # Legacy compatibility aliases:
    "Open",
    "Planned",
    "Fixed",
    "Accepted Risk",
    "Verified",
    "Needs Verification",
}

STATUS_NORMALIZATION_MAP = {
    "open": "Not Started",
    "planned": "In Progress",
    "in progress": "In Progress",
    "fixed": "Fixed Pending Verification",
    "fixed pending verification": "Fixed Pending Verification",
    "verified": "Verified Fixed",
    "verified fixed": "Verified Fixed",
    "reopened": "Reopened",
    "not started": "Not Started",
    "needs verification": "Needs Verification",
    "accepted risk": "Accepted Risk",
}


@router.post(
    "/analyze",
    response_model=DefenderAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Budget-Constrained Remediation Plan",
    description=(
        "Analyzes empirical scan findings produced by the Attacker Agent, calculates technical fixes "
        "and labor costs, and prioritizes remediation actions into three tiers under the specified budget."
    ),
)
def analyze_remediation_budget(request: DefenderAnalysisRequest) -> DefenderAnalysisResponse:
    if request.available_budget <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Available budget must be greater than zero.",
        )

    # If findings are empty but scan_id is provided, try loading from stored scan
    findings = request.findings
    if not findings and request.scan_id:
        scan_record = get_scan_record(request.scan_id)
        if scan_record:
            request.findings = scan_record.get("findings", [])

    engine = DefenderPrioritizationEngine(hourly_rate=request.hourly_rate or 125.0)
    try:
        response = engine.analyze(request)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Defender prioritization engine error: {str(e)}",
        )


@router.patch(
    "/remediation/{scan_id}/{finding_id}/status",
    summary="Update Finding Remediation Status",
    description="Updates tracking state: 'Not Started', 'In Progress', 'Fixed Pending Verification', 'Verified Fixed', or 'Reopened'.",
)
def update_status(
    scan_id: str, finding_id: str, req: RemediationStatusUpdateRequest
) -> Dict[str, Any]:
    norm_status = STATUS_NORMALIZATION_MAP.get(req.status.strip().lower(), req.status)
    if norm_status not in VALID_REMEDIATION_STATUSES and req.status not in VALID_REMEDIATION_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{req.status}'. Must be one of: {sorted(list(VALID_REMEDIATION_STATUSES))}",
        )

    final_status = norm_status

    updated = update_finding_remediation_status(
        scan_id=scan_id,
        finding_id=finding_id,
        status=final_status,
        notes=req.notes,
    )

    if not updated:
        scan = get_scan_record(scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan '{scan_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found under scan '{scan_id}'.",
        )

    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "remediation_status": final_status,
        "notes": req.notes,
        "updated": True,
    }


@router.post(
    "/remediation/{scan_id}/{finding_id}/verify",
    response_model=VerifyRemediationResponse,
    summary="Empirically Verify Remediation with Live Target Check",
    description=(
        "Executes a safe, non-destructive live HTTP check against the target to verify whether the specific "
        "finding has truly been fixed. If the evidence shows the fix is present, transitions status to 'Verified Fixed'. "
        "If the vulnerability still exists, transitions to 'Reopened'. If the check is inconclusive or encounters "
        "a network/proxy error, preserves uncertainty without falsely marking the issue fixed."
    ),
)
def verify_remediation(
    scan_id: str, finding_id: str, req: Optional[VerifyRemediationRequest] = None
) -> VerifyRemediationResponse:
    scan = get_scan_record(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    matching_finding = next((f for f in scan.get("findings", []) if f["id"] == finding_id), None)
    if not matching_finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found under scan '{scan_id}'.",
        )

    target_url = (req.target_url if req and req.target_url else None) or matching_finding.get("affected_url_or_component") or scan.get("target_url")
    prev_status = matching_finding.get("remediation_status", "Not Started")
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    client = SafeHttpClient()
    try:
        norm_url, host, port, path = normalize_target_url(target_url)
        resp = client.request(norm_url, allowed_origin_host=host)
    except Exception as e:
        # Network/connection error -> Inconclusive, retain status and preserve uncertainty
        evidence_summary = f"Verification check failed to connect to target: {str(e)}. Status remains unchanged."
        return VerifyRemediationResponse(
            scan_id=scan_id,
            finding_id=finding_id,
            target_url=target_url,
            previous_status=prev_status,
            new_status=prev_status,
            is_verified=False,
            verification_passed=False,
            is_inconclusive=True,
            evidence_summary=evidence_summary,
            observed_headers={},
            observed_status=None,
            verification_timestamp=now_iso,
            message=evidence_summary,
        )

    # Check for proxy or gateway error
    if resp.is_proxy_or_tunnel_error or resp.status_code in (502, 503, 504, 520, 521, 522, 524):
        evidence_summary = (
            f"Verification inconclusive: HTTP {resp.status_code} received from intermediate gateway "
            f"({resp.proxy_or_tunnel_type or 'Reverse proxy/gateway'}). Target application was not reached."
        )
        return VerifyRemediationResponse(
            scan_id=scan_id,
            finding_id=finding_id,
            target_url=target_url,
            previous_status=prev_status,
            new_status=prev_status,
            is_verified=False,
            verification_passed=False,
            is_inconclusive=True,
            evidence_summary=evidence_summary,
            observed_headers=resp.headers,
            observed_status=resp.status_code,
            verification_timestamp=now_iso,
            message=evidence_summary,
        )

    # Evaluate empirical fix criteria based on finding_id and original evidence
    fix_verified = False
    is_inconclusive = False
    evidence_desc = ""

    # 1. Transport Security: HTTPS Enforcement
    if finding_id == "VULN-TLS-NO-HTTPS":
        # Target must be served over HTTPS or explicitly redirect all HTTP traffic to HTTPS
        fix_verified = resp.was_https or (
            resp.status_code in (301, 302, 307, 308)
            and (resp.get_header("location") or "").lower().startswith("https://")
        )
        evidence_desc = f"Observed protocol: {'HTTPS' if resp.was_https else 'HTTP'}, status: {resp.status_code}, location: {resp.get_header('location') or 'None'}."

    # 2. Strict-Transport-Security (HSTS)
    elif finding_id == "VULN-TLS-MISSING-HSTS":
        # HSTS is only valid when served over HTTPS. If target was queried over HTTP, perform an HTTPS probe.
        hsts_resp = resp
        if not resp.was_https:
            try:
                https_url = f"https://{host}" + (f":{port}" if port not in (80, 443) else "") + (path or "/")
                hsts_resp = client.request(https_url, allowed_origin_host=host)
            except Exception as e:
                hsts_resp = None
                is_inconclusive = True
                evidence_desc = f"HSTS evaluation requires HTTPS, but direct HTTPS probe failed: {str(e)}."

        if not is_inconclusive and hsts_resp is not None:
            if hsts_resp.is_proxy_or_tunnel_error or hsts_resp.status_code in (502, 503, 504, 520, 521, 522, 524):
                is_inconclusive = True
                evidence_desc = f"HTTPS probe received gateway error HTTP {hsts_resp.status_code}."
            elif not hsts_resp.was_https:
                fix_verified = False
                evidence_desc = "Target is not reachable over HTTPS; Strict-Transport-Security cannot be verified."
            else:
                hsts_val = hsts_resp.get_header("Strict-Transport-Security")
                fix_verified = bool(hsts_val and "max-age" in hsts_val.lower())
                evidence_desc = f"Strict-Transport-Security header: {hsts_val or 'ABSENT'}."

    # 3. Content-Security-Policy (CSP)
    elif finding_id == "VULN-SEC-HDR-NO-CSP":
        csp = resp.get_header("Content-Security-Policy")
        fix_verified = bool(csp and len(csp.strip()) > 0)
        evidence_desc = f"Content-Security-Policy header: {csp or 'ABSENT'}."

    # 4. X-Frame-Options / Clickjacking
    elif finding_id == "VULN-SEC-HDR-NO-XFO":
        xfo = resp.get_header("X-Frame-Options")
        csp = resp.get_header("Content-Security-Policy") or ""
        has_valid_xfo = bool(xfo and xfo.strip().lower() in ("deny", "sameorigin"))
        has_valid_csp = "frame-ancestors" in csp.lower()
        fix_verified = has_valid_xfo or has_valid_csp
        evidence_desc = f"X-Frame-Options: {xfo or 'ABSENT'}; CSP frame-ancestors: {'present' if has_valid_csp else 'ABSENT'}."

    # 5. X-Content-Type-Options
    elif finding_id in ("VULN-SEC-HDR-NO-NOSNIFF", "VULN-SEC-HDR-INVALID-NOSNIFF"):
        xcto = resp.get_header("X-Content-Type-Options")
        fix_verified = bool(xcto and "nosniff" in xcto.lower())
        evidence_desc = f"X-Content-Type-Options: {xcto or 'ABSENT'}."

    # 6. Referrer-Policy
    elif finding_id == "VULN-SEC-HDR-NO-REFERRER":
        ref = resp.get_header("Referrer-Policy")
        fix_verified = bool(ref and len(ref.strip()) > 0)
        evidence_desc = f"Referrer-Policy: {ref or 'ABSENT'}."

    # 7. Permissions-Policy
    elif finding_id == "VULN-SEC-HDR-NO-PERMISSIONS":
        perm = resp.get_header("Permissions-Policy")
        fix_verified = bool(perm and len(perm.strip()) > 0)
        evidence_desc = f"Permissions-Policy: {perm or 'ABSENT'}."

    # 8. Server Banner Version Disclosure
    elif finding_id == "VULN-INFO-SERVER-VERSION":
        server = resp.get_header("Server") or ""
        import re
        has_version = bool(re.search(r"/\d+(\.\d+)*", server))
        fix_verified = not has_version
        evidence_desc = f"Server header banner: '{server}'. Specific version disclosed: {has_version}."

    # 9. X-Powered-By Banner
    elif finding_id == "VULN-INFO-X-POWERED-BY":
        xpb = resp.get_header("X-Powered-By")
        fix_verified = not bool(xpb)
        evidence_desc = f"X-Powered-By header: {xpb or 'ABSENT'}."

    # 10. CORS Policy Verification
    elif finding_id == "VULN-CORS-WILDCARD-CREDENTIALS":
        acao = resp.get_header("Access-Control-Allow-Origin")
        acac = resp.get_header("Access-Control-Allow-Credentials")
        # Fixed if wildcard origin is NOT combined with credentials=true
        has_issue = bool(acao == "*" and acac and acac.lower() == "true")
        fix_verified = not has_issue
        evidence_desc = f"Access-Control-Allow-Origin: {acao or 'None'}, Access-Control-Allow-Credentials: {acac or 'None'}."

    elif finding_id == "VULN-CORS-WILDCARD":
        acao = resp.get_header("Access-Control-Allow-Origin")
        fix_verified = bool(acao != "*")
        evidence_desc = f"Access-Control-Allow-Origin: {acao or 'None'}."

    # 11. Cookie Security Flags
    elif finding_id.startswith("VULN-COOKIE-NO-SECURE"):
        # Original cookie name from evidence or finding
        orig_ev = matching_finding.get("evidence") or {}
        orig_cookie = orig_ev.get("observed_data", {}).get("cookie")
        set_cookie_raw = resp.get_header("Set-Cookie") or ""
        cookies = [c.strip() for c in set_cookie_raw.split("\n") if c.strip()]
        
        if not cookies:
            evidence_desc = "No Set-Cookie header issued on response. Cookie flag verification is inconclusive without dynamic session issuance."
            is_inconclusive = True
        else:
            # Check if matching cookie has Secure flag
            cookie_found = False
            has_secure = False
            for c_str in cookies:
                parts = [p.strip() for p in c_str.split(";")]
                c_name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0]
                if not orig_cookie or c_name.lower() == orig_cookie.lower():
                    cookie_found = True
                    lower_parts = [p.lower() for p in parts[1:]]
                    if any(p == "secure" for p in lower_parts):
                        has_secure = True
                        break
            if cookie_found:
                fix_verified = has_secure
                evidence_desc = f"Cookie '{orig_cookie or 'observed'}' has Secure flag: {has_secure}."
            else:
                is_inconclusive = True
                evidence_desc = f"Target cookie '{orig_cookie}' not found in fresh Set-Cookie headers."

    elif finding_id.startswith("VULN-COOKIE-NO-HTTPONLY"):
        orig_ev = matching_finding.get("evidence") or {}
        orig_cookie = orig_ev.get("observed_data", {}).get("cookie")
        set_cookie_raw = resp.get_header("Set-Cookie") or ""
        cookies = [c.strip() for c in set_cookie_raw.split("\n") if c.strip()]

        if not cookies:
            evidence_desc = "No Set-Cookie header issued on response. HttpOnly flag verification is inconclusive without active session issuance."
            is_inconclusive = True
        else:
            cookie_found = False
            has_httponly = False
            for c_str in cookies:
                parts = [p.strip() for p in c_str.split(";")]
                c_name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0]
                if not orig_cookie or c_name.lower() == orig_cookie.lower():
                    cookie_found = True
                    lower_parts = [p.lower() for p in parts[1:]]
                    if any(p == "httponly" for p in lower_parts):
                        has_httponly = True
                        break
            if cookie_found:
                fix_verified = has_httponly
                evidence_desc = f"Cookie '{orig_cookie or 'observed'}' has HttpOnly flag: {has_httponly}."
            else:
                is_inconclusive = True
                evidence_desc = f"Target cookie '{orig_cookie}' not found in fresh Set-Cookie headers."

    # 12. Security.txt Specification
    elif finding_id in ("VULN-BEST-PRACTICE-NO-SECURITY-TXT", "VULN-BEST-PRACTICE-INACCESSIBLE-SECURITY-TXT", "VULN-BEST-PRACTICE-INVALID-SECURITY-TXT"):
        try:
            sec_url = f"{'https' if resp.was_https else 'http'}://{host}" + (f":{port}" if port not in (80, 443) else "") + "/.well-known/security.txt"
            sec_resp = client.request(sec_url, allowed_origin_host=host)
            # Must be HTTP 200, contain Contact: field, and not be an HTML error page
            is_valid_file = (
                sec_resp.status_code == 200
                and "contact:" in sec_resp.body_text.lower()
                and "<html" not in sec_resp.body_text.lower()[:200]
            )
            fix_verified = is_valid_file
            evidence_desc = f"/.well-known/security.txt: status {sec_resp.status_code}, contains valid Contact directive: {is_valid_file}."
        except Exception as e:
            fix_verified = False
            evidence_desc = f"Could not reach /.well-known/security.txt: {str(e)}."

    # 13. Robots.txt Sensitive Paths
    elif finding_id == "VULN-INFO-ROBOTS-SENSITIVE-PATHS":
        try:
            robots_url = f"{'https' if resp.was_https else 'http'}://{host}" + (f":{port}" if port not in (80, 443) else "") + "/robots.txt"
            rob_resp = client.request(robots_url, allowed_origin_host=host)
            import re
            has_sensitive = bool(re.search(r"disallow:\s*/(admin|secret|backup|db|conf|api/v\d+/internal)", rob_resp.body_text, re.IGNORECASE))
            fix_verified = not has_sensitive
            evidence_desc = f"/robots.txt status {rob_resp.status_code}, sensitive paths disclosed: {has_sensitive}."
        except Exception as e:
            fix_verified = False
            evidence_desc = f"Could not reach /robots.txt: {str(e)}."

    else:
        # Unknown or manual finding type -> Inconclusive
        is_inconclusive = True
        evidence_desc = f"No automated protocol heuristic available for finding type '{finding_id}'. Manual code audit required."
        fix_verified = False

    # Handle inconclusive outcomes explicitly: do NOT change status to Verified Fixed or Reopened
    if is_inconclusive:
        verification_evidence_dict = {
            "status_code": resp.status_code,
            "evidence_desc": evidence_desc,
            "fix_verified": False,
            "is_inconclusive": True,
            "verified_at": now_iso,
            "observed_headers": {k: v for k, v in resp.headers.items() if any(t in k.lower() for t in ("security", "strict", "frame", "content", "referrer", "permissions", "server", "powered", "access-control", "cookie"))},
        }
        update_finding_remediation_status(
            scan_id=scan_id,
            finding_id=finding_id,
            status=prev_status,
            notes=f"Inconclusive verification probe: {evidence_desc}",
            verification_evidence=verification_evidence_dict,
        )
        return VerifyRemediationResponse(
            scan_id=scan_id,
            finding_id=finding_id,
            target_url=target_url,
            previous_status=prev_status,
            new_status=prev_status,
            is_verified=False,
            verification_passed=False,
            is_inconclusive=True,
            evidence_summary=evidence_desc,
            observed_headers=verification_evidence_dict["observed_headers"],
            observed_status=resp.status_code,
            verification_timestamp=now_iso,
            message=f"Verification inconclusive: {evidence_desc} Status remains '{prev_status}'.",
        )

    # Conclusive verification outcome: 'Verified Fixed' or 'Reopened'
    new_status = "Verified Fixed" if fix_verified else "Reopened"
    verification_evidence_dict = {
        "status_code": resp.status_code,
        "evidence_desc": evidence_desc,
        "fix_verified": fix_verified,
        "is_inconclusive": False,
        "verified_at": now_iso,
        "observed_headers": {k: v for k, v in resp.headers.items() if any(term in k.lower() for term in ("security", "strict", "frame", "content", "referrer", "permissions", "server", "powered", "access-control", "cookie"))},
    }

    # Persist updated status & verification evidence in database
    update_finding_remediation_status(
        scan_id=scan_id,
        finding_id=finding_id,
        status=new_status,
        notes=f"Empirical verification probe: {evidence_desc}",
        verification_evidence=verification_evidence_dict,
    )

    msg = (
        f"Verification successful: {evidence_desc} Status updated to 'Verified Fixed'."
        if fix_verified
        else f"Verification failed: issue still detectable on wire ({evidence_desc}). Status updated to 'Reopened'."
    )

    return VerifyRemediationResponse(
        scan_id=scan_id,
        finding_id=finding_id,
        target_url=target_url,
        previous_status=prev_status,
        new_status=new_status,
        is_verified=True,
        verification_passed=fix_verified,
        is_inconclusive=False,
        evidence_summary=evidence_desc,
        observed_headers=verification_evidence_dict["observed_headers"],
        observed_status=resp.status_code,
        verification_timestamp=now_iso,
        message=msg,
    )


@router.get(
    "/remediation/{scan_id}/history",
    summary="Get Remediation Status History",
    description="Retrieves the chronological audit log of remediation status changes and verification probes.",
)
def get_status_history(scan_id: str, finding_id: Optional[str] = None) -> Dict[str, Any]:
    history = get_remediation_history(scan_id, finding_id)
    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "total_events": len(history),
        "history": history,
    }


@router.get(
    "/scans/{scan_id}/plan",
    response_model=Dict[str, Any],
    summary="Get Persisted Remediation Plan",
    description="Retrieves the latest budget-aware remediation plan calculated for the given scan.",
)
def get_plan(scan_id: str) -> Dict[str, Any]:
    plan = get_latest_remediation_plan(scan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No remediation plan found for scan '{scan_id}'.",
        )
    return plan


@router.get(
    "/settings",
    summary="Defender Configuration and Cost Rates",
    description="Returns default engineering rates, supported currencies, and valid remediation statuses.",
)
def get_defender_settings() -> Dict[str, Any]:
    return {
        "currencies": ["USD", "EUR", "GBP", "CAD", "AUD"],
        "default_currency": "USD",
        "default_hourly_rate": 125.0,
        "valid_statuses": sorted(list(VALID_REMEDIATION_STATUSES)),
        "lifecycle_stages": [
            "Not Started",
            "In Progress",
            "Fixed Pending Verification",
            "Verified Fixed",
            "Reopened",
        ],
        "cost_assumptions": [
            "Senior Security Engineer rate defaults to $125/hr in selected currency.",
            "Estimates include implementation, local unit testing, and peer review.",
            "Vendor license and external hardware costs are tracked under service_cost.",
            "Estimates are evidence-based models with ±15% variance.",
        ],
    }

