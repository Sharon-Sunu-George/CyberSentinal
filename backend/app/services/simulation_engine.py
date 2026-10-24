from typing import List, Dict, Any
from app.schemas.simulation import (
    AttackSimulationRequest,
    AttackSimulationResponse,
    AttackStage,
    DefenseSimulationRequest,
    DefenseSimulationResponse,
    AppliedDefenseImpact,
)

# Canonical dataset mirrored from frontend mock-data.ts for transparent, deterministic simulation
DEMO_ASSETS: Dict[str, Dict[str, Any]] = {
    "a-pay-prod": {
        "id": "a-pay-prod",
        "name": "Payment Production Server",
        "type": "Application Server",
        "criticality": "Critical",
        "exposure": "Internet-facing",
        "baseline_score": 85.0,
        "controls": {"mfa": "Partial", "edr": "Partial", "patching": "Missing", "segmentation": "Missing", "backup": "Active"},
        "vulnerabilities": ["Unpatched remote code execution in web application framework (CVSS 9.4)", "Exposed debug port"],
        "connected_assets": ["Customer Database", "Payment API Gateway"],
    },
    "a-cust-db": {
        "id": "a-cust-db",
        "name": "Customer Database",
        "type": "Database",
        "criticality": "Critical",
        "exposure": "Internal",
        "baseline_score": 72.0,
        "controls": {"mfa": "Active", "edr": "Partial", "patching": "Partial", "segmentation": "Missing", "backup": "Partial"},
        "vulnerabilities": ["Excessive database service account privileges", "Unencrypted internal replication link"],
        "connected_assets": ["Payment Production Server", "Corporate Identity Server"],
    },
    "a-idp": {
        "id": "a-idp",
        "name": "Corporate Identity Server",
        "type": "Identity Server",
        "criticality": "Critical",
        "exposure": "Internal",
        "baseline_score": 88.0,
        "controls": {"mfa": "Missing", "edr": "Partial", "patching": "Missing", "segmentation": "Missing", "backup": "Active"},
        "vulnerabilities": ["Kerberos ticket delegation vulnerability", "Weak administrative password policy"],
        "connected_assets": ["Customer Database", "Corporate VPN Concentrator", "Developer Workstation"],
    },
    "a-pay-api": {
        "id": "a-pay-api",
        "name": "Payment API Gateway",
        "type": "API Gateway",
        "criticality": "Critical",
        "exposure": "Internet-facing",
        "baseline_score": 64.0,
        "controls": {"mfa": "Active", "edr": "Active", "patching": "Missing", "segmentation": "Partial", "backup": "Active"},
        "vulnerabilities": ["API rate-limiting bypass", "Broken object level authorization (BOLA)"],
        "connected_assets": ["Payment Production Server"],
    },
    "a-vpn": {
        "id": "a-vpn",
        "name": "Corporate VPN Concentrator",
        "type": "Network Appliance",
        "criticality": "Critical",
        "exposure": "Internet-facing",
        "baseline_score": 70.0,
        "controls": {"mfa": "Partial", "edr": "Unavailable", "patching": "Active", "segmentation": "Partial", "backup": "Active"},
        "vulnerabilities": ["Outdated firmware authentication flaw", "Session token reuse vulnerability"],
        "connected_assets": ["Corporate Identity Server", "HR Application Server"],
    },
    "a-backup": {
        "id": "a-backup",
        "name": "Backup Infrastructure",
        "type": "Backup System",
        "criticality": "Critical",
        "exposure": "Internal",
        "baseline_score": 68.0,
        "controls": {"mfa": "Partial", "edr": "Missing", "patching": "Partial", "segmentation": "Partial", "backup": "Missing"},
        "vulnerabilities": ["Unsegmented snapshot replication share", "Default credentials on storage appliance"],
        "connected_assets": ["Customer Database", "Payment Production Server"],
    },
    "a-partner-hub": {
        "id": "a-partner-hub",
        "name": "Partner Integration Hub",
        "type": "Integration Hub",
        "criticality": "Critical",
        "exposure": "Partner network",
        "baseline_score": 65.0,
        "controls": {"mfa": "Active", "edr": "Partial", "patching": "Partial", "segmentation": "Missing", "backup": "Active"},
        "vulnerabilities": ["Third-party API gateway key leakage", "Unrestricted cross-domain CORS policy"],
        "connected_assets": ["Payment API Gateway", "Customer Database"],
    },
    "a-hr-app": {
        "id": "a-hr-app",
        "name": "HR Application Server",
        "type": "Application Server",
        "criticality": "High",
        "exposure": "Internal",
        "baseline_score": 58.0,
        "controls": {"mfa": "Missing", "edr": "Partial", "patching": "Missing", "segmentation": "Partial", "backup": "Active"},
        "vulnerabilities": ["SQL Injection on employee records endpoint", "Outdated Java runtime library"],
        "connected_assets": ["Corporate Identity Server", "Customer Database"],
    },
    "a-mail": {
        "id": "a-mail",
        "name": "Email Gateway",
        "type": "Web Server",
        "criticality": "High",
        "exposure": "Internet-facing",
        "baseline_score": 55.0,
        "controls": {"mfa": "Active", "edr": "Active", "patching": "Active", "segmentation": "Partial", "backup": "Active"},
        "vulnerabilities": ["DMARC policy in monitor-only mode", "Legacy SMTP relay authentication"],
        "connected_assets": ["Corporate Identity Server"],
    },
    "a-dev-ws": {
        "id": "a-dev-ws",
        "name": "Developer Workstation",
        "type": "Workstation",
        "criticality": "Medium",
        "exposure": "Internal",
        "baseline_score": 45.0,
        "controls": {"mfa": "Partial", "edr": "Missing", "patching": "Partial", "segmentation": "Missing", "backup": "Partial"},
        "vulnerabilities": ["Hardcoded AWS credentials in local dotfiles", "Unsigned driver execution enabled"],
        "connected_assets": ["Payment Production Server", "Corporate Identity Server"],
    },
    "a-marketing": {
        "id": "a-marketing",
        "name": "Marketing Website",
        "type": "Web Server",
        "criticality": "Low",
        "exposure": "Internet-facing",
        "baseline_score": 38.0,
        "controls": {"mfa": "Active", "edr": "Partial", "patching": "Partial", "segmentation": "Active", "backup": "Active"},
        "vulnerabilities": ["Outdated WordPress plugin", "Exposed author enumeration endpoint"],
        "connected_assets": ["Internal Wiki"],
    },
    "a-wiki": {
        "id": "a-wiki",
        "name": "Internal Wiki",
        "type": "Web Server",
        "criticality": "Low",
        "exposure": "Internal",
        "baseline_score": 25.0,
        "controls": {"mfa": "Active", "edr": "Active", "patching": "Partial", "segmentation": "Active", "backup": "Active"},
        "vulnerabilities": ["Stored XSS on internal comment page"],
        "connected_assets": ["Developer Workstation"],
    },
}

DEFAULT_ASSET = {
    "id": "a-generic",
    "name": "Generic Monitored Server",
    "type": "Application Server",
    "criticality": "High",
    "exposure": "Internet-facing",
    "baseline_score": 60.0,
    "controls": {"mfa": "Partial", "edr": "Partial", "patching": "Partial", "segmentation": "Missing", "backup": "Active"},
    "vulnerabilities": ["Open service port with missing patch"],
    "connected_assets": ["Internal Subnet"],
}


class AgentSimulationService:
    """
    Deterministic rule-based Attacker & Defender AI Simulation Engine.
    Operates transparently against the authorized demo dataset.
    """

    @classmethod
    def simulate_attack(cls, req: AttackSimulationRequest) -> AttackSimulationResponse:
        asset = DEMO_ASSETS.get(req.asset_id, {**DEFAULT_ASSET, "id": req.asset_id, "name": f"Asset {req.asset_id}"})
        
        intensity_factor = {"low": 0.8, "medium": 1.0, "high": 1.25}.get(req.threat_intensity.lower(), 1.0)
        scenario = req.attack_scenario.lower()

        stages: List[AttackStage] = []
        exploit_factors: List[str] = []
        affected_assets: List[str] = [asset["name"]] + asset.get("connected_assets", [])
        suggested_defenses: List[str] = []

        # Baseline score calculation
        base_score = float(asset.get("baseline_score", 60.0))

        if "vulnerab" in scenario or scenario == "vulnerability_exploitation":
            # Stage 1: Initial Access / Recon
            stages.append(AttackStage(
                stage_number=1,
                name="Initial Access & Vulnerability Probing",
                description=f"Attacker scouts {asset['name']} ({asset['exposure']}) for unpatched vulnerabilities and exposed services.",
                technique="T1190 - Exploit Public-Facing Application",
                success_likelihood=min(0.95, round(0.75 * intensity_factor, 2)),
                evidence=f"Target is {asset['exposure']}; patching control is '{asset['controls'].get('patching', 'Missing')}'."
            ))
            # Stage 2: Exploitation
            vuln_desc = asset["vulnerabilities"][0] if asset["vulnerabilities"] else "Unpatched software component"
            stages.append(AttackStage(
                stage_number=2,
                name="Payload Execution & Code Execution",
                description=f"Attacker delivers exploit targeting: {vuln_desc}.",
                technique="T1059 - Command and Scripting Interpreter",
                success_likelihood=min(0.90, round(0.70 * intensity_factor, 2)),
                evidence=f"EDR control is '{asset['controls'].get('edr', 'Partial')}'; zero automated remediation triggered."
            ))
            # Stage 3: Lateral Movement / Impact
            stages.append(AttackStage(
                stage_number=3,
                name="Lateral Pivot & Data Infiltration",
                description=f"Pivot from {asset['name']} to interconnected systems: {', '.join(asset.get('connected_assets', ['internal network']))}.",
                technique="T1021 - Remote Services & Lateral Movement",
                success_likelihood=min(0.85, round(0.60 * intensity_factor, 2)),
                evidence=f"Network segmentation is '{asset['controls'].get('segmentation', 'Missing')}'; lateral traffic uninspected."
            ))
            simulated_score = min(100.0, round(base_score + (12.0 * intensity_factor), 1))
            exploit_factors.append("Unpatched critical vulnerability")
            exploit_factors.append("Missing network segmentation barriers")
            suggested_defenses.extend(["patching", "segmentation", "edr"])

        elif "unauthorized" in scenario or scenario == "unauthorized_access":
            stages.append(AttackStage(
                stage_number=1,
                name="Credential Spraying & Identity Probing",
                description=f"Attacker attempts unauthorized authentication against {asset['name']}.",
                technique="T1110 - Brute Force / Credential Stuffing",
                success_likelihood=min(0.90, round(0.65 * intensity_factor, 2)),
                evidence=f"MFA status is '{asset['controls'].get('mfa', 'Missing')}' on target authentication endpoints."
            ))
            stages.append(AttackStage(
                stage_number=2,
                name="Session Hijacking & Token Replay",
                description=f"Successful unauthorized session established on {asset['name']}.",
                technique="T1550 - Use Alternate Authentication Material",
                success_likelihood=min(0.85, round(0.60 * intensity_factor, 2)),
                evidence="Session reuse vulnerability detected; no anomaly alert raised."
            ))
            stages.append(AttackStage(
                stage_number=3,
                name="Administrative Pivot & Persistence",
                description=f"Adversary uses stolen token to access {', '.join(asset.get('connected_assets', ['internal resources']))}.",
                technique="T1078 - Valid Accounts",
                success_likelihood=min(0.80, round(0.55 * intensity_factor, 2)),
                evidence=f"EDR status is '{asset['controls'].get('edr', 'Partial')}'; account anomaly uncontained."
            ))
            simulated_score = min(100.0, round(base_score + (10.0 * intensity_factor), 1))
            exploit_factors.append("Incomplete MFA enforcement")
            exploit_factors.append("Weak session timeout controls")
            suggested_defenses.extend(["mfa", "edr", "segmentation"])

        else: # privilege_escalation or other
            stages.append(AttackStage(
                stage_number=1,
                name="Local Environment Discovery",
                description=f"Attacker investigates misconfigurations and internal service tokens on {asset['name']}.",
                technique="T1082 - System Information Discovery",
                success_likelihood=min(0.95, round(0.80 * intensity_factor, 2)),
                evidence="Local audit logging partial; service account permissions wide."
            ))
            stages.append(AttackStage(
                stage_number=2,
                name="Privilege Escalation to Root/Domain Admin",
                description="Attacker leverages misconfigured service credentials to obtain administrative control.",
                technique="T1068 - Exploitation for Privilege Escalation",
                success_likelihood=min(0.85, round(0.65 * intensity_factor, 2)),
                evidence=f"Identity controls in '{asset['controls'].get('mfa', 'Missing')}' state; elevated token granted."
            ))
            stages.append(AttackStage(
                stage_number=3,
                name="Defense Evasion & Credential Dumping",
                description="Adversary disables audit logging and extracts local hashes.",
                technique="T1003 - OS Credential Dumping",
                success_likelihood=min(0.80, round(0.60 * intensity_factor, 2)),
                evidence=f"Patch status is '{asset['controls'].get('patching', 'Missing')}'; kernel exploits viable."
            ))
            simulated_score = min(100.0, round(base_score + (15.0 * intensity_factor), 1))
            exploit_factors.append("Excessive administrative privileges")
            exploit_factors.append("Lack of multi-factor authorization for sensitive tasks")
            suggested_defenses.extend(["mfa", "patching", "edr"])

        impact_desc = (
            f"Simulated compromise of {asset['name']} ({asset['criticality']} criticality) could risk disruption "
            f"to {len(affected_assets)} connected systems and expose sensitive business operations."
        )

        return AttackSimulationResponse(
            asset_id=req.asset_id,
            asset_name=asset["name"],
            attack_scenario=req.attack_scenario,
            threat_intensity=req.threat_intensity,
            baseline_risk_score=base_score,
            simulated_risk_score=simulated_score,
            is_compromise_modeled=True,
            stages=stages,
            affected_assets=affected_assets,
            potential_business_impact=impact_desc,
            exploit_factors=exploit_factors,
            suggested_defenses=list(dict.fromkeys(suggested_defenses)),
        )

    @classmethod
    def simulate_defense(cls, req: DefenseSimulationRequest) -> DefenseSimulationResponse:
        asset = DEMO_ASSETS.get(req.asset_id, {**DEFAULT_ASSET, "id": req.asset_id, "name": f"Asset {req.asset_id}"})
        
        # Explicit deterministic point reductions per control
        CONTROL_VALUES: Dict[str, Dict[str, Any]] = {
            "patching": {
                "name": "Security Patch Deployment",
                "points": 14.0,
                "reason": "Eliminates known public exploit vectors and addresses unpatched vulnerabilities.",
            },
            "mfa": {
                "name": "Multi-Factor Authentication (MFA)",
                "points": 12.0,
                "reason": "Blocks credential stuffing, brute force attempts, and unauthorized session establishment.",
            },
            "segmentation": {
                "name": "Micro-Segmentation & East-West Filtering",
                "points": 10.0,
                "reason": "Restricts lateral pivot attempts to connected internal databases and services.",
            },
            "edr": {
                "name": "Endpoint Detection & Response (EDR)",
                "points": 8.0,
                "reason": "Enhances anomaly detection, memory inspection, and automated containment response.",
            },
        }

        applied_list: List[AppliedDefenseImpact] = []
        total_reduction = 0.0

        for ctrl in req.selected_controls:
            ctrl_key = ctrl.lower().strip()
            if ctrl_key in CONTROL_VALUES:
                c_info = CONTROL_VALUES[ctrl_key]
                applied_list.append(AppliedDefenseImpact(
                    control_id=ctrl_key,
                    control_name=c_info["name"],
                    mitigation_reason=c_info["reason"],
                    points_reduced=c_info["points"],
                ))
                total_reduction += c_info["points"]

        # Calculate residual risk score
        pre_score = req.simulated_risk_score
        residual = max(15.0, round(pre_score - total_reduction, 1))
        abs_reduction = round(pre_score - residual, 1)
        pct_reduction = round((abs_reduction / pre_score) * 100.0, 1) if pre_score > 0 else 0.0

        # Determine remaining weaknesses
        remaining_weaknesses: List[str] = []
        all_possible = set(CONTROL_VALUES.keys())
        selected_set = set(c.lower().strip() for c in req.selected_controls)
        unselected = all_possible - selected_set

        if "patching" in unselected:
            remaining_weaknesses.append("Unpatched CVE vulnerabilities remain exposed to exploit delivery.")
        if "mfa" in unselected:
            remaining_weaknesses.append("Single-factor authentication paths remain susceptible to credential attacks.")
        if "segmentation" in unselected:
            remaining_weaknesses.append("Flat network path allows lateral movement to connected databases.")
        if "edr" in unselected:
            remaining_weaknesses.append("Host-level behavioral detection blindspots persist.")

        if not remaining_weaknesses:
            remaining_weaknesses.append("Defense-in-depth controls fully applied across tested parameters.")

        # Next recommendation
        if residual <= 35.0:
            next_action = "Maintain active telemetry and schedule regular recurring patch verifications."
        elif residual <= 60.0:
            next_action = "Apply remaining unselected defensive controls to reduce residual exposure below medium threshold."
        else:
            next_action = "CRITICAL: Deploy comprehensive patching and MFA immediately to prevent high-risk compromise."

        return DefenseSimulationResponse(
            asset_id=req.asset_id,
            asset_name=asset["name"],
            pre_defense_risk_score=pre_score,
            residual_risk_score=residual,
            absolute_risk_reduction=abs_reduction,
            percentage_risk_reduction=pct_reduction,
            applied_controls=applied_list,
            remaining_weaknesses=remaining_weaknesses,
            recommended_next_action=next_action,
        )
