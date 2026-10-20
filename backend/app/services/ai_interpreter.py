import os
import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from app.schemas.report import ReportFinding, NormalizedRiskScenario

logger = logging.getLogger(__name__)


class AiInterpreterService:
    """
    AI Interpretation Service for unstructured documents.
    Safely interprets document text when configured, and provides robust deterministic
    rule-based extraction when no AI provider is configured.
    Treats all document text strictly as UNTRUSTED passive data.
    """

    @classmethod
    def get_provider_status(cls) -> Tuple[bool, str, str]:
        """
        Returns (is_configured, provider_name, details).
        """
        if os.getenv("OPENAI_API_KEY"):
            return True, "OpenAI", "Configured via OPENAI_API_KEY"
        if os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"):
            return True, "Google Gemini", "Configured via GEMINI_API_KEY"
        if os.getenv("ANTHROPIC_API_KEY"):
            return True, "Anthropic Claude", "Configured via ANTHROPIC_API_KEY"

        return (
            False,
            "Deterministic Rule-Based Parser",
            "No external AI API key configured. Deterministic regex & heuristic rule parser is active.",
        )

    @classmethod
    def extract_from_unstructured_text(
        cls,
        text: str,
        filename: str = "document",
    ) -> Dict[str, Any]:
        """
        Extracts structured security findings and risk scenarios from unstructured document text.
        If an AI provider is configured, queries it safely.
        Otherwise, uses the deterministic rule-based extractor and reports limitations clearly.
        """
        is_ai_configured, provider_name, details = cls.get_provider_status()

        if is_ai_configured:
            try:
                return cls._query_llm_extractor(text, filename, provider_name)
            except Exception as e:
                logger.warning(f"AI extraction failed, falling back to rule-based parser: {e}")
                result = cls._deterministic_rule_based_extract(text, filename)
                result["warnings"].append(
                    f"AI provider ({provider_name}) request failed: {str(e)}. Fallback deterministic extractor was applied."
                )
                result["ai_status"] = f"FAILED ({str(e)})"
                return result

        result = cls._deterministic_rule_based_extract(text, filename)
        result["warnings"].append(
            "AI Provider is not configured (set OPENAI_API_KEY or GEMINI_API_KEY). "
            "Report was parsed using deterministic pattern matching. Deep narrative interpretation is unavailable."
        )
        result["ai_status"] = "NOT_CONFIGURED"
        return result

    @classmethod
    def _deterministic_rule_based_extract(cls, text: str, filename: str) -> Dict[str, Any]:
        """
        Deterministic regex and structural parser for security reports, pentests, audit notes,
        and risk documents. Never fabricates missing numerical data.
        """
        findings: List[ReportFinding] = []
        scenarios: List[NormalizedRiskScenario] = []
        warnings: List[str] = []
        missing_fields: List[str] = []

        # 1. Extract Target / Host / System
        target = "Extracted Document Target"
        target_match = re.search(r"(?:Target|Host|System|Asset|URL|Domain)\s*[:=-]\s*([^\r\n,;]+)", text, re.IGNORECASE)
        if target_match:
            target = target_match.group(1).strip()

        # 2. Extract explicit CVEs
        raw_cves = re.findall(r"\bCVE[-_ ]?(\d{4})[-_ ]?(\d{3,7})\b", text, re.IGNORECASE)
        normalized_cves = [f"CVE-{year}-{num}" for year, num in raw_cves]
        unique_cves = list(dict.fromkeys(normalized_cves))

        # 3. Search for structured finding blocks or bullet points
        finding_blocks = re.split(
            r"\n(?=(?:\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]|\b(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\b:?|\bFinding\s+\d+|(?:\d+\.))\s+)",
            text,
            flags=re.IGNORECASE,
        )

        item_idx = 1
        for block in finding_blocks:
            block_clean = block.strip()
            if not block_clean or len(block_clean) < 8:
                continue

            # Skip block if it looks like just a document header/financial summary without finding markers
            first_line = block_clean.split("\n")[0].strip()
            is_explicit_finding_header = bool(
                re.match(r"^(?:\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]|\b(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\b:?|\bFinding\s+\d+|(?:\d+\.))\s+", first_line, re.IGNORECASE)
            )

            sev_match = re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\b", block_clean, re.IGNORECASE)
            cve_in_block = re.search(r"\bCVE[-_ ]?(\d{4})[-_ ]?(\d{3,7})\b", block_clean, re.IGNORECASE)
            cvss_match = re.search(r"\b(?:CVSS(?:[:\s]+v\d)?|Base\s+Score|Score)\s*[:=]?\s*([0-9]\.[0-9])\b", block_clean, re.IGNORECASE)
            rec_match = re.search(r"(?:Remediation|Recommendation|Mitigation|Fix)\s*[:=-]\s*([^\r\n]+)", block_clean, re.IGNORECASE)

            # Only treat as a finding if it has an explicit finding header, or contains CVE/CVSS, or is explicitly tagged with finding keywords
            has_finding_marker = is_explicit_finding_header or cve_in_block or cvss_match or "vulnerability" in block_clean.lower()
            is_just_summary = "penetration test report" in first_line.lower() and not is_explicit_finding_header and not cve_in_block

            if has_finding_marker and not is_just_summary:
                title = re.sub(
                    r"^(?:\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]|\b(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\b:?|\d+\.|\-|\*|Finding\s+\d+:?)\s*",
                    "",
                    first_line,
                    flags=re.IGNORECASE,
                ).strip()
                if not title or len(title) > 120:
                    title = f"Security Finding {item_idx}"

                severity = "Medium"
                if sev_match:
                    raw_s = sev_match.group(1).upper()
                    if "CRIT" in raw_s:
                        severity = "Critical"
                    elif "HI" in raw_s:
                        severity = "High"
                    elif "LOW" in raw_s or "INFO" in raw_s:
                        severity = "Low"
                    else:
                        severity = "Medium"

                cvss_val = None
                if cvss_match:
                    try:
                        cvss_val = float(cvss_match.group(1))
                    except ValueError:
                        pass

                cve_val = f"CVE-{cve_in_block.group(1)}-{cve_in_block.group(2)}" if cve_in_block else None
                rec_val = rec_match.group(1).strip() if rec_match else None

                findings.append(
                    ReportFinding(
                        id=f"FINDING-{item_idx}",
                        title=title,
                        severity=severity,
                        cvss_score=cvss_val,
                        cve=cve_val,
                        asset=target,
                        evidence=block_clean[:200] + ("..." if len(block_clean) > 200 else ""),
                        recommendation=rec_val,
                        is_inferred=False,
                        source="explicit_document_text",
                    )
                )
                item_idx += 1

        # Fallback line-by-line scanner if no findings were extracted by block splitter
        if not findings:
            for line in text.splitlines():
                line_str = line.strip()
                if not line_str or len(line_str) < 5:
                    continue
                # Check if line contains security keywords or CVEs
                cve_match = re.search(r"\bCVE[-_ ]?(\d{4})[-_ ]?(\d{3,7})\b", line_str, re.IGNORECASE)
                sev_match = re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", line_str, re.IGNORECASE)
                has_alert = any(kw in line_str.lower() for kw in ("alert", "threat", "vulnerability", "risk", "exploit"))

                if cve_match or sev_match or has_alert:
                    sev = "Medium"
                    if sev_match:
                        raw_s = sev_match.group(1).upper()
                        sev = "Critical" if "CRIT" in raw_s else "High" if "HI" in raw_s else "Low" if "LOW" in raw_s else "Medium"
                    elif "critical" in line_str.lower():
                        sev = "Critical"
                    elif "high" in line_str.lower():
                        sev = "High"

                    cve_val = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}" if cve_match else None
                    title = re.sub(r"^(?:\[?[A-Z]+\]?|\d+\.|\-|\*)\s*", "", line_str).strip()
                    findings.append(
                        ReportFinding(
                            id=f"FINDING-{item_idx}",
                            title=title or f"Detected Finding {item_idx}",
                            severity=sev,
                            cve=cve_val,
                            asset=target,
                            evidence=line_str,
                            is_inferred=False,
                            source="explicit_line_scan",
                        )
                    )
                    item_idx += 1

        # 4. Extract explicit financial/quantitative numbers if present in text
        val_match = re.search(r"Asset\s+Value\s*[:=-]\s*\$?([0-9,]+(?:\.[0-9]+)?)", text, re.IGNORECASE)
        tef_match = re.search(r"(?:Threat\s+Event\s+Frequency|TEF|Annual\s+Frequency|Frequency)\s*[:=-]\s*([0-9]+(?:\.[0-9]+)?)", text, re.IGNORECASE)
        vuln_prob_match = re.search(r"(?:Vulnerability\s+Probability|Vuln\s+Prob|Vulnerability)\s*[:=-]\s*([0-9]+(?:\.[0-9]+)?%?)", text, re.IGNORECASE)
        direct_loss_match = re.search(r"Direct\s+Loss\s*[:=-]\s*\$?([0-9,]+(?:\.[0-9]+)?)", text, re.IGNORECASE)
        indirect_loss_match = re.search(r"Indirect\s+Loss\s*[:=-]\s*\$?([0-9,]+(?:\.[0-9]+)?)", text, re.IGNORECASE)
        sec_cost_match = re.search(r"(?:Proposed\s+Security\s+Cost|Control\s+Cost|Security\s+Cost)\s*[:=-]\s*\$?([0-9,]+(?:\.[0-9]+)?)", text, re.IGNORECASE)

        asset_value = float(val_match.group(1).replace(",", "")) if val_match else None
        tef = float(tef_match.group(1)) if tef_match else None

        vuln_prob = None
        if vuln_prob_match:
            raw_vp = vuln_prob_match.group(1).strip()
            if raw_vp.endswith("%"):
                vuln_prob = float(raw_vp[:-1]) / 100.0
            else:
                vuln_prob = float(raw_vp)
                if vuln_prob > 1.0:
                    vuln_prob = vuln_prob / 100.0

        direct_loss = float(direct_loss_match.group(1).replace(",", "")) if direct_loss_match else None
        indirect_loss = float(indirect_loss_match.group(1).replace(",", "")) if indirect_loss_match else None
        sec_cost = float(sec_cost_match.group(1).replace(",", "")) if sec_cost_match else None

        # Check what is missing
        for f_name, f_val in [
            ("asset_value", asset_value),
            ("threat_event_frequency", tef),
            ("vulnerability_probability", vuln_prob),
            ("direct_loss", direct_loss),
            ("indirect_loss", indirect_loss),
        ]:
            if f_val is None:
                missing_fields.append(f_name)

        if missing_fields:
            warnings.append(
                f"Missing quantitative FAIR inputs: {', '.join(missing_fields)}. "
                "FAIR risk calculations require explicit numerical values. Values were NOT invented."
            )

        if asset_value or tef or direct_loss or indirect_loss:
            scenarios.append(
                NormalizedRiskScenario(
                    scenario_id="SCENARIO-EXTRACTED-1",
                    scenario_name=f"Quantified Risk Profile for {target}",
                    asset_name=target,
                    asset_value=asset_value,
                    threat_event_frequency=tef,
                    vulnerability_probability=vuln_prob,
                    direct_loss=direct_loss,
                    indirect_loss=indirect_loss,
                    proposed_security_cost=sec_cost,
                    is_inferred=False,
                )
            )

        return {
            "target": target,
            "findings": findings,
            "scenarios": scenarios,
            "warnings": warnings,
            "missing_fields": missing_fields,
            "ai_status": "NOT_CONFIGURED",
        }

    @classmethod
    def _query_llm_extractor(cls, text: str, filename: str, provider: str) -> Dict[str, Any]:
        """
        Securely query configured LLM provider. Wraps document text as untrusted data.
        """
        truncated_text = text[:15000]

        prompt = (
            "You are a cybersecurity risk parser. You are analyzing an untrusted security document. "
            "Extract structured findings and risk scenarios in JSON format. "
            "CRITICAL: Do NOT invent numerical financial data (direct_loss, indirect_loss, asset_value, threat_event_frequency) "
            "if not explicitly stated in the document. Mark inferred items with is_inferred=true.\n\n"
            f"<UNTRUSTED_DOCUMENT_DATA filename=\"{filename}\">\n{truncated_text}\n</UNTRUSTED_DOCUMENT_DATA>\n\n"
            "Return valid JSON with keys: 'target', 'findings' (list of {id, title, severity, cvss_score, cve, asset, recommendation, is_inferred}), "
            "'scenarios' (list of {scenario_id, scenario_name, asset_name, asset_value, threat_event_frequency, vulnerability_probability, direct_loss, indirect_loss, is_inferred}), "
            "'warnings' (list of strings)."
        )

        if provider == "OpenAI":
            import urllib.request
            api_key = os.getenv("OPENAI_API_KEY")
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=json.dumps({
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity risk data parser. Return only JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.0,
                }).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                content = resp_data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                parsed["ai_status"] = "USED (OpenAI gpt-4o-mini)"
                return parsed

        return cls._deterministic_rule_based_extract(text, filename)
