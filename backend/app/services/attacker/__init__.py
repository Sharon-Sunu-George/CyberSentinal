"""
Attacker Agent package for CyberQuant.
"""

from app.services.attacker.agent import AttackerAgentService
from app.services.attacker.scanner import EvidenceBasedScanner, SafeHttpClient, SafeHttpResponse
from app.services.attacker.ssrf_guard import (
    SSRFProtectionError,
    TargetAuthorizationError,
    normalize_target_url,
    resolve_and_verify_ip,
    get_local_dev_target_config,
    validate_destination_url,
)

__all__ = [
    "AttackerAgentService",
    "EvidenceBasedScanner",
    "SafeHttpClient",
    "SafeHttpResponse",
    "SSRFProtectionError",
    "TargetAuthorizationError",
    "normalize_target_url",
    "resolve_and_verify_ip",
    "get_local_dev_target_config",
    "validate_destination_url",
]
