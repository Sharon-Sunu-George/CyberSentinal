import json
from typing import Any, Dict, List, Optional, Union
from app.schemas.report import ParsedReportResponse, ReportFinding, ReportSummary
from app.services.document_parser import (
    DocumentParserService,
    DocumentParserError,
    DocumentSecurityError,
)


class ReportParserError(DocumentParserError):
    """Raised when security report file fails validation or structural parsing."""
    pass


class ReportParserService:
    """
    Deterministic security report parser service.
    Processes structured JSON, CSV, TXT, DOCX, PDF, and PNG/JPG security reports.
    """

    @classmethod
    async def parse_document(cls, filename: str, content_bytes: bytes) -> ParsedReportResponse:
        """
        Parses multi-format document using DocumentParserService.
        """
        return await DocumentParserService.parse_document(filename, content_bytes)

    @classmethod
    def parse_json_report(cls, raw_content: Union[str, bytes], filename: str = "report.json") -> ParsedReportResponse:
        """
        Backward compatible synchronous JSON parsing method.
        """
        if isinstance(raw_content, str):
            content_bytes = raw_content.encode("utf-8")
        else:
            content_bytes = raw_content

        try:
            return DocumentParserService.parse_json(filename, content_bytes)
        except DocumentParserError as e:
            raise ReportParserError(str(e))
