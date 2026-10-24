import os
from fastapi import APIRouter, File, UploadFile, HTTPException, status
from app.schemas.report import ParsedReportResponse
from app.services.report_parser import ReportParserService
from app.services.document_parser import DocumentParserError, DocumentSecurityError

router = APIRouter()

SUPPORTED_EXTENSIONS = {".json", ".csv", ".txt", ".docx", ".pdf", ".png", ".jpg", ".jpeg"}


@router.post(
    "/upload",
    response_model=ParsedReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload and Parse Security Report / Document",
    description=(
        "Processes security reports and risk documents across multiple formats (JSON, CSV, TXT, DOCX, PDF, PNG, JPG). "
        "Extracts structured risk scenarios, findings, CVSS scores, remediation recommendations, and executes FAIR risk calculations."
    ),
)
async def upload_report(file: UploadFile = File(...)) -> ParsedReportResponse:
    """
    Accepts an uploaded security report or document in JSON, CSV, TXT, DOCX, PDF, or PNG/JPEG format.
    Deterministically extracts findings and scenarios, computes FAIR metrics via the risk engine when
    quantitative numbers are present, distinguishes stated facts from inferences, and safely handles untrusted data.
    """
    filename = file.filename or "unknown_report"
    ext = os.path.splitext(filename.lower())[1]

    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported file format '{filename}'. "
                f"Supported formats: JSON (.json), CSV (.csv), TXT (.txt), Word (.docx), PDF (.pdf), and Images (.png, .jpg, .jpeg)."
            ),
        )

    try:
        content_bytes = await file.read()
        if len(content_bytes) == 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Uploaded file is empty (0 bytes).",
            )

        if len(content_bytes) > 25 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File size exceeds maximum allowable limit of 25MB.",
            )

        parsed_report = await ReportParserService.parse_document(filename, content_bytes)
        return parsed_report

    except DocumentSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security rejection: {str(e)}",
        )
    except DocumentParserError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Document parsing error: {str(e)}",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error while processing report: {str(e)}",
        )
