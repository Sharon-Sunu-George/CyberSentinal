import csv
import io
import json
import logging
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple, Union

from app.schemas.report import (
    NormalizedRiskScenario,
    ParsedReportResponse,
    ReportFinding,
    ReportSummary,
)
from app.schemas.risk import RiskAssessmentRequest, RiskMetrics
from app.services.ai_interpreter import AiInterpreterService
from app.services.ocr_service import OcrError, OcrService
from app.services.risk_engine import RiskEngineService

logger = logging.getLogger(__name__)


class DocumentParserError(ValueError):
    """Raised when document parsing, validation, or processing fails."""
    pass


class DocumentSecurityError(ValueError):
    """Raised when an uploaded file fails security checks (e.g. executable signature)."""
    pass


class DocumentParserService:
    """
    Unified multi-format document parser for CyberQuant.
    Supports CSV, JSON, TXT, DOCX, text-based PDF, scanned PDF, and PNG/JPEG images.
    """

    MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB

    @classmethod
    def detect_format_and_validate(cls, filename: str, content_bytes: bytes) -> str:
        """
        Validates file size, file extensions, and file signatures.
        Rejects executable binaries and malformed containers.
        Returns normalized format string: 'JSON', 'CSV', 'TXT', 'DOCX', 'PDF', 'PNG', 'JPG'.
        """
        if not content_bytes or len(content_bytes) == 0:
            raise DocumentParserError("Uploaded file is empty (0 bytes).")

        if len(content_bytes) > cls.MAX_FILE_SIZE:
            raise DocumentParserError(f"File size exceeds maximum allowable limit of 25MB ({len(content_bytes)} bytes).")

        ext = os.path.splitext(filename.lower())[1]

        # Security check: Disallow executable file signatures
        # Windows MZ header
        if content_bytes.startswith(b"MZ"):
            raise DocumentSecurityError("Security Violation: Executable binaries (PE/MZ) are not permitted.")
        # Linux ELF header
        if content_bytes.startswith(b"\x7fELF"):
            raise DocumentSecurityError("Security Violation: Executable binaries (ELF) are not permitted.")
        # Mach-O header
        if content_bytes.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")):
            raise DocumentSecurityError("Security Violation: Executable binaries (Mach-O) are not permitted.")

        # PNG format
        if ext == ".png" or content_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            if not content_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                raise DocumentParserError("Invalid PNG file: Missing standard PNG header signature.")
            return "PNG"

        # JPG/JPEG format
        if ext in (".jpg", ".jpeg") or content_bytes.startswith(b"\xff\xd8\xff"):
            if not content_bytes.startswith(b"\xff\xd8\xff"):
                raise DocumentParserError("Invalid JPEG file: Missing standard JPEG header signature.")
            return "JPG"

        # PDF format
        if ext == ".pdf" or content_bytes.startswith(b"%PDF-"):
            if not content_bytes.startswith(b"%PDF-"):
                raise DocumentParserError("Invalid PDF file: Missing standard '%PDF-' header signature.")
            return "PDF"

        # DOCX format (Zip archive containing [Content_Types].xml or word/document.xml)
        if ext == ".docx" or content_bytes.startswith(b"PK\x03\x04"):
            if not content_bytes.startswith(b"PK\x03\x04"):
                raise DocumentParserError("Invalid DOCX file: Not a valid OpenXML package.")
            try:
                with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
                    namelist = zf.namelist()
                    if not any("word/" in name or "[Content_Types].xml" in name for name in namelist):
                        raise DocumentParserError("Invalid DOCX file: Missing WordprocessingML structures.")
            except zipfile.BadZipFile:
                raise DocumentParserError("Corrupted DOCX file: Unable to unzip package contents.")
            return "DOCX"

        # JSON format
        if ext == ".json":
            return "JSON"

        # CSV format
        if ext == ".csv":
            return "CSV"

        # TXT format
        if ext == ".txt":
            return "TXT"

        # Content sniffing fallback for text/json if extension was missing
        stripped = content_bytes.strip()
        if stripped.startswith((b"{", b"[")):
            return "JSON"

        raise DocumentParserError(
            f"Unsupported file format '{filename}'. Supported formats are: CSV, JSON, TXT, DOCX, PDF, PNG, JPG/JPEG."
        )

    @classmethod
    def sanitize_untrusted_text(cls, text: str) -> str:
        """
        Removes non-printable control characters (preserving tab, newline, carriage return).
        Prevents binary terminal injection and malicious control sequences.
        """
        # Keep printable chars and standard whitespace
        return "".join(ch for ch in text if ch in "\t\n\r" or ch >= " ")

    @classmethod
    async def parse_document(cls, filename: str, content_bytes: bytes) -> ParsedReportResponse:
        """
        Main entry point for processing all supported formats.
        """
        clean_filename = os.path.basename(filename) or "uploaded_report"
        detected_fmt = cls.detect_format_and_validate(clean_filename, content_bytes)

        if detected_fmt == "JSON":
            return cls.parse_json(clean_filename, content_bytes)
        elif detected_fmt == "CSV":
            return cls.parse_csv(clean_filename, content_bytes)
        elif detected_fmt == "TXT":
            return cls.parse_txt(clean_filename, content_bytes)
        elif detected_fmt == "DOCX":
            return cls.parse_docx(clean_filename, content_bytes)
        elif detected_fmt == "PDF":
            return await cls.parse_pdf(clean_filename, content_bytes)
        elif detected_fmt in ("PNG", "JPG"):
            return await cls.parse_image(clean_filename, content_bytes, detected_fmt)
        else:
            raise DocumentParserError(f"Unhandled file format '{detected_fmt}'.")

    # -------------------------------------------------------------------------
    # 1. JSON Parser
    # -------------------------------------------------------------------------
    @classmethod
    def parse_json(cls, filename: str, content_bytes: bytes) -> ParsedReportResponse:
        """
        Deterministically parses JSON security scan reports or FAIR risk scenario files.
        """
        try:
            raw_text = content_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as e:
            raise DocumentParserError(f"Invalid JSON encoding. File must be UTF-8 encoded text: {str(e)}")

        if not raw_text.strip():
            raise DocumentParserError("Uploaded JSON report file is empty.")

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as e:
            raise DocumentParserError(f"Malformed JSON syntax: {e.msg} at line {e.lineno}, column {e.colno}")

        # Check if the JSON is a single FAIR risk scenario or list of scenarios
        if isinstance(data, dict) and any(k in data for k in ("scenario_name", "threat_event_frequency", "direct_loss", "scenarios")):
            return cls._parse_fair_scenario_json(filename, data)
        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and "scenario_name" in data[0]:
            return cls._parse_fair_scenario_json(filename, {"scenarios": data})

        # Otherwise parse as standard security scan report
        if not isinstance(data, dict):
            raise DocumentParserError("JSON root must be an object representing the security report or risk scenario.")

        report_id = str(data.get("report_id") or data.get("id") or f"REPORT-{clean_id(filename)}").strip()
        target = str(data.get("target") or data.get("target_url") or data.get("host") or "Unknown Target").strip()
        report_date = data.get("report_date") or data.get("date") or data.get("scan_date")
        environment = data.get("environment")
        report_type = data.get("report_type")
        notice = data.get("notice")

        is_synthetic = False
        if environment and "test" in str(environment).lower():
            is_synthetic = True
        if report_type and "synthetic" in str(report_type).lower():
            is_synthetic = True
        if notice and ("synthetic" in str(notice).lower() or "fictional" in str(notice).lower()):
            is_synthetic = True

        raw_findings = data.get("findings")
        if raw_findings is None:
            # Check if this JSON has any vulnerability or risk items under different keys
            for alt_key in ("vulnerabilities", "issues", "results", "alerts"):
                if isinstance(data.get(alt_key), list):
                    raw_findings = data.get(alt_key)
                    break

        if raw_findings is None or not isinstance(raw_findings, list):
            raise DocumentParserError("Missing required 'findings' array in report JSON.")

        parsed_findings: List[ReportFinding] = []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for idx, item in enumerate(raw_findings):
            if not isinstance(item, dict):
                raise DocumentParserError(f"Finding at index {idx} must be a JSON object.")

            f_id = item.get("id") or f"FINDING-{idx + 1}"
            title = item.get("title") or item.get("name")
            if not title:
                raise DocumentParserError(f"Finding at index {idx} (ID: {f_id}) is missing a 'title'.")

            normalized_sev = normalize_severity(str(item.get("severity") or "Low"))
            sev_key = normalized_sev.lower()
            if sev_key in counts:
                counts[sev_key] += 1

            raw_cvss = item.get("cvss_score") or item.get("cvss")
            cvss_score = None
            if raw_cvss is not None:
                try:
                    cvss_score = float(raw_cvss)
                    if cvss_score < 0.0 or cvss_score > 10.0:
                        raise ValueError()
                except (ValueError, TypeError):
                    raise DocumentParserError(
                        f"Finding '{title}' has invalid cvss_score: {raw_cvss}. Must be a float between 0.0 and 10.0."
                    )

            cve = item.get("cve") or item.get("cve_id")
            asset = item.get("asset") or item.get("affected_component") or item.get("target") or target
            evidence = item.get("evidence")
            recommendation = item.get("recommendation") or item.get("remediation")

            parsed_findings.append(
                ReportFinding(
                    id=str(f_id).strip(),
                    title=str(title).strip(),
                    severity=normalized_sev,
                    cvss_score=cvss_score,
                    cve=str(cve).strip() if cve else None,
                    asset=str(asset).strip() if asset else None,
                    evidence=evidence,
                    recommendation=str(recommendation).strip() if recommendation else None,
                    is_inferred=False,
                    source="explicit_json_report",
                )
            )

        summary = ReportSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            total_findings=len(parsed_findings),
        )

        warnings = []
        missing_fields = ["asset_value", "threat_event_frequency", "vulnerability_probability", "direct_loss", "indirect_loss"]
        warnings.append(
            "Security report parsed deterministically. Quantitative FAIR financial loss parameters (direct_loss, indirect_loss, TEF) "
            "were not provided in this findings report and were not fabricated."
        )

        return ParsedReportResponse(
            report_id=report_id,
            target=target,
            filename=filename,
            detected_format="JSON",
            report_date=str(report_date) if report_date else None,
            environment=str(environment) if environment else None,
            report_type=str(report_type) if report_type else None,
            notice=str(notice) if notice else None,
            is_synthetic=is_synthetic,
            summary=summary,
            findings=parsed_findings,
            scenarios=[],
            warnings=warnings,
            missing_fields=missing_fields,
            analysis_status="COMPLETED",
            ai_status="NOT_NEEDED",
            ocr_status="NOT_NEEDED",
        )

    @classmethod
    def _parse_fair_scenario_json(cls, filename: str, data: Dict[str, Any]) -> ParsedReportResponse:
        """
        Parses structured FAIR risk scenarios from JSON and calculates financial metrics with RiskEngineService.
        """
        raw_scenarios = data.get("scenarios") if "scenarios" in data else [data]
        if not isinstance(raw_scenarios, list):
            raw_scenarios = [data]

        normalized_scenarios: List[NormalizedRiskScenario] = []
        findings: List[ReportFinding] = []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_baseline_ale = 0.0
        total_mitigated_ale = 0.0
        warnings: List[str] = []
        missing_fields: List[str] = []

        target = data.get("target") or data.get("asset_name") or "Enterprise IT Infrastructure"

        for idx, sc_item in enumerate(raw_scenarios):
            if not isinstance(sc_item, dict):
                continue

            sc_name = str(sc_item.get("scenario_name") or f"Risk Scenario {idx + 1}").strip()
            asset_name = str(sc_item.get("asset_name") or target).strip()

            # Validate numerical values
            asset_val = to_optional_float(sc_item.get("asset_value"))
            tef = to_optional_float(sc_item.get("threat_event_frequency") or sc_item.get("tef"))
            vuln_prob = to_optional_float(sc_item.get("vulnerability_probability") or sc_item.get("vuln_prob"))
            direct_loss = to_optional_float(sc_item.get("direct_loss"))
            indirect_loss = to_optional_float(sc_item.get("indirect_loss"))
            sec_cost = to_optional_float(sc_item.get("proposed_security_cost") or sc_item.get("security_cost"))
            mit_prob = to_optional_float(sc_item.get("mitigated_vulnerability_probability"))

            # Check if all required FAIR fields are present
            req_fields = {
                "asset_value": asset_val,
                "threat_event_frequency": tef,
                "vulnerability_probability": vuln_prob,
                "direct_loss": direct_loss,
                "indirect_loss": indirect_loss,
            }
            scenario_missing = [k for k, v in req_fields.items() if v is None]
            for m in scenario_missing:
                if m not in missing_fields:
                    missing_fields.append(m)

            calculated_metrics: Optional[RiskMetrics] = None
            assumptions: List[str] = []
            recommendation: Optional[str] = None

            if not scenario_missing:
                # All required numerical inputs are present! Use existing FastAPI risk engine!
                req = RiskAssessmentRequest(
                    scenario_name=sc_name,
                    asset_name=asset_name,
                    asset_value=asset_val,
                    threat_event_frequency=tef,
                    vulnerability_probability=vuln_prob,
                    direct_loss=direct_loss,
                    indirect_loss=indirect_loss,
                    proposed_security_cost=sec_cost or 0.0,
                    mitigated_vulnerability_probability=mit_prob,
                )
                assessment = RiskEngineService.calculate_single_risk(req)
                calculated_metrics = assessment.metrics
                assumptions = assessment.assumptions
                recommendation = assessment.recommendation
                total_baseline_ale += calculated_metrics.annual_loss_expectancy
                if calculated_metrics.mitigated_annual_loss_expectancy:
                    total_mitigated_ale += calculated_metrics.mitigated_annual_loss_expectancy

            # Classify severity based on ALE or impact
            ale = calculated_metrics.annual_loss_expectancy if calculated_metrics else 0.0
            if ale >= 500000:
                sev = "Critical"
            elif ale >= 100000:
                sev = "High"
            elif ale >= 25000:
                sev = "Medium"
            else:
                sev = "Low"
            counts[sev.lower()] += 1

            norm_sc = NormalizedRiskScenario(
                scenario_id=f"SCENARIO-{idx + 1}",
                scenario_name=sc_name,
                asset_name=asset_name,
                asset_value=asset_val,
                threat_event_frequency=tef,
                vulnerability_probability=vuln_prob,
                direct_loss=direct_loss,
                indirect_loss=indirect_loss,
                proposed_security_cost=sec_cost,
                mitigated_vulnerability_probability=mit_prob,
                is_inferred=False,
                metrics=calculated_metrics,
                assumptions=assumptions,
                recommendation=recommendation,
            )
            normalized_scenarios.append(norm_sc)

            findings.append(
                ReportFinding(
                    id=f"SCENARIO-FINDING-{idx + 1}",
                    title=f"Quantified Risk: {sc_name}",
                    severity=sev,
                    cvss_score=min(10.0, round(ale / 100000, 1)) if ale > 0 else None,
                    asset=asset_name,
                    evidence=f"Baseline ALE: ${ale:,.2f}" if calculated_metrics else "Quantitative parameters incomplete",
                    recommendation=recommendation,
                    is_inferred=False,
                    source="structured_fair_json",
                )
            )

        if missing_fields:
            warnings.append(
                f"Missing numerical fields for full FAIR calculations: {', '.join(missing_fields)}. "
                "Inputs were NOT fabricated; partial scenarios evaluated."
            )

        # Aggregate metrics
        overall_metrics = None
        if total_baseline_ale > 0:
            overall_metrics = RiskMetrics(
                loss_event_frequency=1.0,
                single_loss_expectancy=round(total_baseline_ale, 2),
                annual_loss_expectancy=round(total_baseline_ale, 2),
                mitigated_annual_loss_expectancy=round(total_mitigated_ale, 2) if total_mitigated_ale > 0 else None,
                annual_risk_reduction=round(total_baseline_ale - total_mitigated_ale, 2) if total_mitigated_ale > 0 else None,
            )

        summary = ReportSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            total_findings=len(findings),
        )

        return ParsedReportResponse(
            report_id=f"FAIR-{clean_id(filename)}",
            target=target,
            filename=filename,
            detected_format="JSON (FAIR Scenarios)",
            report_date=data.get("report_date"),
            environment=data.get("environment"),
            report_type="FAIR Quantitative Risk Scenarios",
            is_synthetic=False,
            summary=summary,
            findings=findings,
            scenarios=normalized_scenarios,
            calculated_metrics=overall_metrics,
            warnings=warnings,
            missing_fields=missing_fields,
            analysis_status="COMPLETED",
            ai_status="NOT_NEEDED",
            ocr_status="NOT_NEEDED",
        )

    # -------------------------------------------------------------------------
    # 2. CSV Parser
    # -------------------------------------------------------------------------
    @classmethod
    def parse_csv(cls, filename: str, content_bytes: bytes) -> ParsedReportResponse:
        """
        Deterministically parses structured CSV files.
        Supports both FAIR risk scenarios tables and vulnerability findings tables.
        """
        try:
            raw_text = content_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                raw_text = content_bytes.decode("latin-1")
            except Exception as e:
                raise DocumentParserError(f"Unable to decode CSV text: {str(e)}")

        if not raw_text.strip():
            raise DocumentParserError("Uploaded CSV file is empty.")

        # Determine delimiter
        first_line = raw_text.splitlines()[0]
        delimiter = ","
        if "\t" in first_line:
            delimiter = "\t"
        elif ";" in first_line and first_line.count(";") > first_line.count(","):
            delimiter = ";"

        reader = csv.DictReader(io.StringIO(raw_text), delimiter=delimiter)
        if not reader.fieldnames:
            raise DocumentParserError("CSV file contains no column headers.")

        # Normalize field names: strip quotes and lowercase
        normalized_headers = {h.strip().lower().replace(" ", "_"): h for h in reader.fieldnames if h}

        # Check if CSV represents FAIR risk scenarios or security findings
        is_fair_scenario_csv = any(
            h in normalized_headers
            for h in ("scenario_name", "threat_event_frequency", "tef", "direct_loss", "asset_value")
        )

        rows = list(reader)
        if not rows:
            raise DocumentParserError("CSV contains headers but no data rows.")

        if is_fair_scenario_csv:
            return cls._parse_fair_scenario_csv(filename, rows, normalized_headers)
        else:
            return cls._parse_vulnerability_csv(filename, rows, normalized_headers)

    @classmethod
    def _parse_fair_scenario_csv(
        cls,
        filename: str,
        rows: List[Dict[str, str]],
        headers: Dict[str, str],
    ) -> ParsedReportResponse:
        """
        Parses FAIR quantitative risk scenario rows from CSV and computes calculations via RiskEngineService.
        """
        def get_col(row: Dict[str, str], *aliases: str) -> Optional[str]:
            for alias in aliases:
                norm_alias = alias.lower().replace(" ", "_")
                if norm_alias in headers:
                    val = row.get(headers[norm_alias])
                    if val is not None and str(val).strip():
                        return str(val).strip()
            return None

        normalized_scenarios: List[NormalizedRiskScenario] = []
        findings: List[ReportFinding] = []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_baseline_ale = 0.0
        total_mitigated_ale = 0.0
        missing_fields: List[str] = []
        warnings: List[str] = []

        first_target = "Enterprise IT Infrastructure"

        for idx, row in enumerate(rows):
            sc_name = get_col(row, "scenario_name", "scenario", "name", "title") or f"CSV Scenario {idx + 1}"
            asset_name = get_col(row, "asset_name", "asset", "target", "system") or "Asset Infrastructure"
            if idx == 0:
                first_target = asset_name

            asset_val = to_optional_float(get_col(row, "asset_value", "value", "asset_val"))
            tef = to_optional_float(get_col(row, "threat_event_frequency", "tef", "frequency", "threat_frequency"))
            vuln_prob = to_optional_float(get_col(row, "vulnerability_probability", "vuln_prob", "probability", "vulnerability"))
            direct_loss = to_optional_float(get_col(row, "direct_loss", "direct_cost", "direct"))
            indirect_loss = to_optional_float(get_col(row, "indirect_loss", "indirect_cost", "indirect"))
            sec_cost = to_optional_float(get_col(row, "proposed_security_cost", "security_cost", "control_cost"))
            mit_prob = to_optional_float(get_col(row, "mitigated_vulnerability_probability", "mitigated_prob", "mitigated_vuln"))

            req_fields = {
                "asset_value": asset_val,
                "threat_event_frequency": tef,
                "vulnerability_probability": vuln_prob,
                "direct_loss": direct_loss,
                "indirect_loss": indirect_loss,
            }
            row_missing = [k for k, v in req_fields.items() if v is None]
            for m in row_missing:
                if m not in missing_fields:
                    missing_fields.append(m)

            calculated_metrics = None
            assumptions = []
            recommendation = None

            if not row_missing:
                # Valid numerical inputs: calculate using RiskEngineService!
                req = RiskAssessmentRequest(
                    scenario_name=sc_name,
                    asset_name=asset_name,
                    asset_value=asset_val,
                    threat_event_frequency=tef,
                    vulnerability_probability=vuln_prob,
                    direct_loss=direct_loss,
                    indirect_loss=indirect_loss,
                    proposed_security_cost=sec_cost or 0.0,
                    mitigated_vulnerability_probability=mit_prob,
                )
                assessment = RiskEngineService.calculate_single_risk(req)
                calculated_metrics = assessment.metrics
                assumptions = assessment.assumptions
                recommendation = assessment.recommendation
                total_baseline_ale += calculated_metrics.annual_loss_expectancy
                if calculated_metrics.mitigated_annual_loss_expectancy:
                    total_mitigated_ale += calculated_metrics.mitigated_annual_loss_expectancy

            ale = calculated_metrics.annual_loss_expectancy if calculated_metrics else 0.0
            if ale >= 500000:
                sev = "Critical"
            elif ale >= 100000:
                sev = "High"
            elif ale >= 25000:
                sev = "Medium"
            else:
                sev = "Low"
            counts[sev.lower()] += 1

            norm_sc = NormalizedRiskScenario(
                scenario_id=f"CSV-SCENARIO-{idx + 1}",
                scenario_name=sc_name,
                asset_name=asset_name,
                asset_value=asset_val,
                threat_event_frequency=tef,
                vulnerability_probability=vuln_prob,
                direct_loss=direct_loss,
                indirect_loss=indirect_loss,
                proposed_security_cost=sec_cost,
                mitigated_vulnerability_probability=mit_prob,
                is_inferred=False,
                metrics=calculated_metrics,
                assumptions=assumptions,
                recommendation=recommendation,
            )
            normalized_scenarios.append(norm_sc)

            findings.append(
                ReportFinding(
                    id=f"CSV-FIND-{idx + 1}",
                    title=f"Quantified Scenario: {sc_name}",
                    severity=sev,
                    cvss_score=min(10.0, round(ale / 100000, 1)) if ale > 0 else None,
                    asset=asset_name,
                    evidence=f"Direct Loss: ${direct_loss:,.2f}, Indirect Loss: ${indirect_loss:,.2f}" if direct_loss and indirect_loss else None,
                    recommendation=recommendation,
                    is_inferred=False,
                    source="csv_fair_data",
                )
            )

        if missing_fields:
            warnings.append(
                f"Missing numerical columns in CSV: {', '.join(missing_fields)}. "
                "FAIR loss calculations require explicit numbers; values were NOT fabricated."
            )

        overall_metrics = None
        if total_baseline_ale > 0:
            overall_metrics = RiskMetrics(
                loss_event_frequency=1.0,
                single_loss_expectancy=round(total_baseline_ale, 2),
                annual_loss_expectancy=round(total_baseline_ale, 2),
                mitigated_annual_loss_expectancy=round(total_mitigated_ale, 2) if total_mitigated_ale > 0 else None,
                annual_risk_reduction=round(total_baseline_ale - total_mitigated_ale, 2) if total_mitigated_ale > 0 else None,
            )

        summary = ReportSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            total_findings=len(findings),
        )

        return ParsedReportResponse(
            report_id=f"CSV-{clean_id(filename)}",
            target=first_target,
            filename=filename,
            detected_format="CSV (FAIR Risk Scenarios)",
            report_type="CSV Risk Scenario Table",
            is_synthetic=False,
            summary=summary,
            findings=findings,
            scenarios=normalized_scenarios,
            calculated_metrics=overall_metrics,
            warnings=warnings,
            missing_fields=missing_fields,
            analysis_status="COMPLETED",
            ai_status="NOT_NEEDED",
            ocr_status="NOT_NEEDED",
        )

    @classmethod
    def _parse_vulnerability_csv(
        cls,
        filename: str,
        rows: List[Dict[str, str]],
        headers: Dict[str, str],
    ) -> ParsedReportResponse:
        """
        Parses vulnerability finding rows from CSV.
        """
        def get_col(row: Dict[str, str], *aliases: str) -> Optional[str]:
            for alias in aliases:
                norm_alias = alias.lower().replace(" ", "_")
                if norm_alias in headers:
                    val = row.get(headers[norm_alias])
                    if val is not None and str(val).strip():
                        return str(val).strip()
            return None

        findings: List[ReportFinding] = []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        target = "Scanned Asset"

        for idx, row in enumerate(rows):
            f_id = get_col(row, "id", "finding_id", "vuln_id", "cve") or f"CSV-FIND-{idx + 1}"
            title = get_col(row, "title", "name", "vulnerability", "issue", "finding")
            if not title:
                title = f"Vulnerability {idx + 1}"

            raw_sev = get_col(row, "severity", "level", "risk", "priority") or "Medium"
            sev = normalize_severity(raw_sev)
            counts[sev.lower()] += 1

            cvss = to_optional_float(get_col(row, "cvss_score", "cvss", "score"))
            cve = get_col(row, "cve", "cve_id")
            asset = get_col(row, "asset", "host", "target", "ip", "system") or target
            if idx == 0 and asset != target:
                target = asset

            rec = get_col(row, "recommendation", "remediation", "mitigation", "solution")
            evidence = get_col(row, "evidence", "proof", "details", "description")

            findings.append(
                ReportFinding(
                    id=str(f_id),
                    title=str(title),
                    severity=sev,
                    cvss_score=cvss,
                    cve=cve,
                    asset=asset,
                    evidence=evidence,
                    recommendation=rec,
                    is_inferred=False,
                    source="csv_vulnerability_table",
                )
            )

        summary = ReportSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            total_findings=len(findings),
        )

        missing_fields = ["asset_value", "threat_event_frequency", "vulnerability_probability", "direct_loss", "indirect_loss"]
        warnings = [
            "Parsed CSV vulnerability findings table. Quantitative FAIR financial loss parameters (direct_loss, indirect_loss, TEF) "
            "were not in this table and were not fabricated."
        ]

        return ParsedReportResponse(
            report_id=f"CSV-SCAN-{clean_id(filename)}",
            target=target,
            filename=filename,
            detected_format="CSV (Vulnerability Findings)",
            report_type="CSV Vulnerability Scan Results",
            is_synthetic=False,
            summary=summary,
            findings=findings,
            scenarios=[],
            warnings=warnings,
            missing_fields=missing_fields,
            analysis_status="COMPLETED",
            ai_status="NOT_NEEDED",
            ocr_status="NOT_NEEDED",
        )

    # -------------------------------------------------------------------------
    # 3. TXT Parser
    # -------------------------------------------------------------------------
    @classmethod
    def parse_txt(cls, filename: str, content_bytes: bytes) -> ParsedReportResponse:
        """
        Extracts and parses plain text documents (.txt).
        Uses AiInterpreterService to extract structured findings and risk scenarios.
        """
        for enc in ("utf-8-sig", "utf-8", "latin-1", "utf-16"):
            try:
                raw_text = content_bytes.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            raise DocumentParserError("Failed to decode text file. Ensure it is a valid text encoding.")

        sanitized_text = cls.sanitize_untrusted_text(raw_text)
        if not sanitized_text.strip():
            raise DocumentParserError("Uploaded text document is empty.")

        extracted = AiInterpreterService.extract_from_unstructured_text(sanitized_text, filename)
        return cls._build_unstructured_response(
            filename=filename,
            detected_format="TXT",
            extracted_text=sanitized_text,
            extracted_data=extracted,
            ocr_status="NOT_NEEDED",
        )

    # -------------------------------------------------------------------------
    # 4. DOCX Parser
    # -------------------------------------------------------------------------
    @classmethod
    def parse_docx(cls, filename: str, content_bytes: bytes) -> ParsedReportResponse:
        """
        Extracts text from Microsoft Word (.docx) documents.
        Processes paragraphs, tables, and lists.
        """
        extracted_paragraphs: List[str] = []

        try:
            import docx
            doc = docx.Document(io.BytesIO(content_bytes))
            for p in doc.paragraphs:
                p_text = p.text.strip()
                if p_text:
                    extracted_paragraphs.append(p_text)

            for table in doc.tables:
                for row in table.rows:
                    row_cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                    if row_cells:
                        extracted_paragraphs.append(" | ".join(row_cells))
        except Exception as e:
            logger.warning(f"python-docx parsing failed, trying raw XML extraction: {e}")
            # Fallback to direct XML parsing from zip archive
            try:
                with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
                    xml_content = zf.read("word/document.xml").decode("utf-8", errors="replace")
                    # Strip XML tags
                    text_only = re.sub(r"<[^>]+>", " ", xml_content)
                    cleaned = " ".join(text_only.split())
                    if cleaned:
                        extracted_paragraphs.append(cleaned)
            except Exception as zip_e:
                raise DocumentParserError(f"Failed to extract Word document content: {str(e)}; fallback error: {str(zip_e)}")

        full_text = "\n".join(extracted_paragraphs)
        sanitized_text = cls.sanitize_untrusted_text(full_text)
        if not sanitized_text.strip():
            raise DocumentParserError("Word document contains no extractable text.")

        extracted = AiInterpreterService.extract_from_unstructured_text(sanitized_text, filename)
        return cls._build_unstructured_response(
            filename=filename,
            detected_format="DOCX",
            extracted_text=sanitized_text,
            extracted_data=extracted,
            ocr_status="NOT_NEEDED",
        )

    # -------------------------------------------------------------------------
    # 5. PDF Parser (Embedded Text + Scanned OCR)
    # -------------------------------------------------------------------------
    @classmethod
    async def parse_pdf(cls, filename: str, content_bytes: bytes) -> ParsedReportResponse:
        """
        Extracts embedded text from PDF.
        Detects scanned / image-only PDFs and executes OCR on page images.
        """
        try:
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(content_bytes))
        except Exception as e:
            raise DocumentParserError(f"Failed to read PDF document: {str(e)}")

        if len(reader.pages) == 0:
            raise DocumentParserError("Uploaded PDF contains zero pages.")

        page_texts = []
        for p in reader.pages:
            try:
                t = p.extract_text()
                if t:
                    page_texts.append(t.strip())
            except Exception:
                pass

        embedded_text = "\n".join(page_texts).strip()
        is_scanned_pdf = False
        detected_format = "PDF (Embedded Text)"
        ocr_status = "NOT_NEEDED"
        warnings: List[str] = []

        # If extracted embedded text is minimal or empty, treat as scanned PDF
        if len(embedded_text) < 50:
            is_scanned_pdf = True
            detected_format = "PDF (Scanned - OCR Extracted)"
            logger.info(f"PDF '{filename}' detected as scanned document. Invoking OCR engine...")

            ocr_available, ocr_desc = OcrService.get_status()
            if not ocr_available:
                raise DocumentParserError(
                    f"PDF '{filename}' is a scanned or image-only document, but no OCR engine is configured on this system ({ocr_desc}). "
                    "Cannot extract text without OCR."
                )

            ocr_page_texts = []
            for p_idx, page in enumerate(reader.pages):
                if hasattr(page, "images"):
                    for img_idx, img_obj in enumerate(page.images):
                        try:
                            # img_obj.data is bytes
                            ocr_text = await OcrService.extract_text_from_image_bytes(
                                img_obj.data,
                                f"{filename}_p{p_idx+1}_img{img_idx+1}"
                            )
                            if ocr_text:
                                ocr_page_texts.append(ocr_text)
                        except Exception as ocr_err:
                            logger.warning(f"OCR failed for image on page {p_idx+1}: {ocr_err}")

            if ocr_page_texts:
                embedded_text = "\n".join(ocr_page_texts).strip()
                ocr_status = f"USED ({ocr_desc})"
            else:
                ocr_status = "FAILED"
                warnings.append("OCR engine executed on scanned PDF but could not extract readable text from page images.")

        sanitized_text = cls.sanitize_untrusted_text(embedded_text)
        if not sanitized_text.strip():
            raise DocumentParserError(
                f"PDF '{filename}' contains no readable text. Embedded text extraction returned empty, and OCR yielded no text."
            )

        extracted = AiInterpreterService.extract_from_unstructured_text(sanitized_text, filename)
        if warnings:
            extracted.setdefault("warnings", []).extend(warnings)

        return cls._build_unstructured_response(
            filename=filename,
            detected_format=detected_format,
            extracted_text=sanitized_text,
            extracted_data=extracted,
            ocr_status=ocr_status,
        )

    # -------------------------------------------------------------------------
    # 6. Image Parser (PNG / JPG OCR)
    # -------------------------------------------------------------------------
    @classmethod
    async def parse_image(cls, filename: str, content_bytes: bytes, image_fmt: str) -> ParsedReportResponse:
        """
        Uses OCR to extract text from PNG or JPG/JPEG scanned images.
        """
        ocr_available, ocr_desc = OcrService.get_status()
        if not ocr_available:
            raise DocumentParserError(
                f"Image upload requires OCR, but no OCR engine is available ({ocr_desc}). "
                "Please enable Windows Media OCR or install Tesseract-OCR."
            )

        try:
            extracted_text = await OcrService.extract_text_from_image_bytes(content_bytes, filename)
        except OcrError as e:
            raise DocumentParserError(f"OCR failed to process image: {str(e)}")

        sanitized_text = cls.sanitize_untrusted_text(extracted_text)
        if not sanitized_text.strip():
            raise DocumentParserError(
                f"OCR executed successfully on {image_fmt} image, but detected no readable text. "
                "Ensure image has sufficient contrast and resolution."
            )

        extracted = AiInterpreterService.extract_from_unstructured_text(sanitized_text, filename)
        return cls._build_unstructured_response(
            filename=filename,
            detected_format=f"Image ({image_fmt} - OCR Extracted)",
            extracted_text=sanitized_text,
            extracted_data=extracted,
            ocr_status=f"USED ({ocr_desc})",
        )

    # -------------------------------------------------------------------------
    # Helper to build consistent response for unstructured text documents
    # -------------------------------------------------------------------------
    @classmethod
    def _build_unstructured_response(
        cls,
        filename: str,
        detected_format: str,
        extracted_text: str,
        extracted_data: Dict[str, Any],
        ocr_status: str,
    ) -> ParsedReportResponse:
        """
        Normalizes findings, scenarios, and calculates metrics when quantitative data is present.
        """
        findings: List[ReportFinding] = extracted_data.get("findings", [])
        scenarios: List[NormalizedRiskScenario] = extracted_data.get("scenarios", [])
        warnings: List[str] = extracted_data.get("warnings", [])
        missing_fields: List[str] = extracted_data.get("missing_fields", [])
        ai_status: str = extracted_data.get("ai_status", "NOT_CONFIGURED")
        target: str = extracted_data.get("target") or "Extracted Target System"

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1

        # Run RiskEngineService on scenarios that have required fields
        calculated_metrics = None
        for sc in scenarios:
            if (
                sc.asset_value is not None
                and sc.threat_event_frequency is not None
                and sc.vulnerability_probability is not None
                and sc.direct_loss is not None
                and sc.indirect_loss is not None
            ):
                req = RiskAssessmentRequest(
                    scenario_name=sc.scenario_name,
                    asset_name=sc.asset_name,
                    asset_value=sc.asset_value,
                    threat_event_frequency=sc.threat_event_frequency,
                    vulnerability_probability=sc.vulnerability_probability,
                    direct_loss=sc.direct_loss,
                    indirect_loss=sc.indirect_loss,
                    proposed_security_cost=sc.proposed_security_cost or 0.0,
                    mitigated_vulnerability_probability=sc.mitigated_vulnerability_probability,
                )
                assessment = RiskEngineService.calculate_single_risk(req)
                sc.metrics = assessment.metrics
                sc.assumptions = assessment.assumptions
                sc.recommendation = assessment.recommendation
                calculated_metrics = assessment.metrics

        summary = ReportSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            total_findings=len(findings),
        )

        # Preview of extracted text (first 600 chars)
        preview = extracted_text[:600] + ("..." if len(extracted_text) > 600 else "")

        return ParsedReportResponse(
            report_id=f"DOC-{clean_id(filename)}",
            target=target,
            filename=filename,
            detected_format=detected_format,
            report_date=None,
            report_type="Unstructured Security Document",
            is_synthetic=False,
            summary=summary,
            findings=findings,
            scenarios=scenarios,
            extracted_text_preview=preview,
            calculated_metrics=calculated_metrics,
            warnings=warnings,
            missing_fields=missing_fields,
            analysis_status="COMPLETED" if findings or scenarios else "PARTIAL",
            ai_status=ai_status,
            ocr_status=ocr_status,
        )


def clean_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", s)[:32]


def normalize_severity(raw: str) -> str:
    s = raw.strip().upper()
    if "CRIT" in s:
        return "Critical"
    elif "HI" in s:
        return "High"
    elif "MED" in s:
        return "Medium"
    elif "LOW" in s or "INFO" in s:
        return "Low"
    return "Medium"


def to_optional_float(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        s = str(val).replace("$", "").replace(",", "").replace("%", "").strip()
        if not s:
            return None
        f = float(s)
        # If original had %, divide by 100
        if "%" in str(val) and f > 1.0:
            f = f / 100.0
        return f
    except (ValueError, TypeError):
        return None
