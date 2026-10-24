import io
import logging
from typing import Tuple, Optional
from PIL import Image

logger = logging.getLogger(__name__)

class OcrError(Exception):
    """Raised when OCR processing fails."""
    pass


class OcrService:
    """
    OCR abstraction layer supporting native Windows OCR (winocr) and Tesseract (pytesseract).
    Gracefully detects availability and handles image extraction.
    """

    @classmethod
    def get_status(cls) -> Tuple[bool, str]:
        """
        Returns (is_available, provider_description).
        """
        # 1. Check winocr
        try:
            import winocr
            return True, "Windows Media OCR Engine (winocr)"
        except Exception:
            pass

        # 2. Check pytesseract
        try:
            import pytesseract
            import shutil
            if shutil.which("tesseract"):
                return True, "Tesseract OCR Engine (pytesseract)"
        except Exception:
            pass

        return False, "No OCR engine available (Install Tesseract-OCR or enable Windows Media OCR)"

    @classmethod
    async def extract_text_from_image_bytes(cls, image_bytes: bytes, filename: str = "image") -> str:
        """
        Extracts text from image bytes using the best available OCR engine.
        """
        if not image_bytes:
            raise OcrError("Empty image data provided for OCR.")

        try:
            image = Image.open(io.BytesIO(image_bytes))
            # Convert to RGB if needed
            if image.mode not in ("L", "RGB"):
                image = image.convert("RGB")
        except Exception as e:
            raise OcrError(f"Failed to open image file '{filename}': {str(e)}")

        return await cls.extract_text_from_pil(image, filename)

    @classmethod
    async def extract_text_from_pil(cls, image: Image.Image, filename: str = "image") -> str:
        """
        Extracts text from a PIL Image.
        """
        errors = []

        # Try winocr
        try:
            import winocr
            result = await winocr.recognize_pil(image, "en")
            if result and hasattr(result, "text"):
                text = (result.text or "").strip()
                return text
        except Exception as e:
            logger.warning(f"winocr extraction failed: {e}")
            errors.append(f"winocr: {str(e)}")

        # Try pytesseract
        try:
            import pytesseract
            text = pytesseract.image_to_string(image)
            return (text or "").strip()
        except Exception as e:
            logger.warning(f"pytesseract extraction failed: {e}")
            errors.append(f"pytesseract: {str(e)}")

        is_avail, desc = cls.get_status()
        if not is_avail:
            raise OcrError(f"OCR service is not available on this system ({desc}). Image text extraction could not be completed.")

        raise OcrError(f"OCR extraction failed for image '{filename}': {'; '.join(errors)}")
