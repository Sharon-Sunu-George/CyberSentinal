"""
Threat Intelligence Provider Interface and Concrete Adapters.
Integrates Google Safe Browsing and PhishTank behind a clean abstraction.
All API keys are read from environment variables on the backend only.
Includes in-memory TTL caching, timeouts, error isolation, and honest reporting.
"""

import datetime
import json
import logging
import os
import time
import urllib.parse
import urllib.request
from typing import Optional, Dict, Any, List

from app.schemas.trust import ThreatIntelligenceMatch

logger = logging.getLogger(__name__)

# Cache duration in seconds (default: 30 minutes)
INTEL_CACHE_TTL_SECONDS = 1800

# In-memory thread-safe cache: (provider, url_or_domain) -> (expiry_epoch, ThreatIntelligenceMatch)
_INTEL_CACHE: Dict[str, tuple[float, ThreatIntelligenceMatch]] = {}


def _get_cached_match(cache_key: str) -> Optional[ThreatIntelligenceMatch]:
    now = time.time()
    if cache_key in _INTEL_CACHE:
        expiry, match = _INTEL_CACHE[cache_key]
        if now < expiry:
            # Return copy with cached=True
            match_dict = match.model_dump()
            match_dict["cached"] = True
            return ThreatIntelligenceMatch(**match_dict)
        else:
            del _INTEL_CACHE[cache_key]
    return None


def _set_cached_match(cache_key: str, match: ThreatIntelligenceMatch, ttl: float = INTEL_CACHE_TTL_SECONDS) -> None:
    _INTEL_CACHE[cache_key] = (time.time() + ttl, match)


class ThreatIntelProvider:
    """Base interface for threat intelligence feeds."""
    name: str = "Base Provider"

    def is_configured(self) -> bool:
        raise NotImplementedError

    def lookup_url(self, url: str) -> ThreatIntelligenceMatch:
        raise NotImplementedError


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    """
    Google Safe Browsing v4 threatMatches:find API client.
    Docs: https://developers.google.com/safe-browsing/reference/rest/v4/threatMatches/find
    API key must be provided in GOOGLE_SAFE_BROWSING_API_KEY environment variable.
    """
    name = "Google Safe Browsing"

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key

    @property
    def api_key(self) -> Optional[str]:
        return self._api_key or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    def is_configured(self) -> bool:
        key = self.api_key
        return bool(key and key.strip())

    def lookup_url(self, url: str) -> ThreatIntelligenceMatch:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cache_key = f"gsb:{url}"
        cached = _get_cached_match(cache_key)
        if cached:
            return cached

        if not self.is_configured():
            return ThreatIntelligenceMatch(
                provider=self.name,
                status="unconfigured",
                details="Google Safe Browsing API key (GOOGLE_SAFE_BROWSING_API_KEY) is not configured.",
                lookup_timestamp=now_iso,
            )

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {
                "clientId": "cybersentinel-platform",
                "clientVersion": "2.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "CyberSentinal/2.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                status_code = resp.status
                body = resp.read().decode("utf-8")
                data = json.loads(body)

                matches = data.get("matches", [])
                if matches:
                    primary_threat = matches[0].get("threatType", "SOCIAL_ENGINEERING")
                    match_obj = ThreatIntelligenceMatch(
                        provider=self.name,
                        status="match_detected",
                        threat_type=primary_threat,
                        details=f"Positive match identified in Google Safe Browsing threat lists: {primary_threat}",
                        lookup_timestamp=now_iso,
                        reference_url="https://transparencyreport.google.com/safe-browsing/search",
                    )
                else:
                    match_obj = ThreatIntelligenceMatch(
                        provider=self.name,
                        status="no_match",
                        details="No threat matches returned by Google Safe Browsing.",
                        lookup_timestamp=now_iso,
                    )

                _set_cached_match(cache_key, match_obj)
                return match_obj

        except urllib.error.HTTPError as e:
            logger.warning(f"Google Safe Browsing HTTP {e.code}: {e.reason}")
            return ThreatIntelligenceMatch(
                provider=self.name,
                status="service_unavailable" if e.code in (429, 500, 502, 503) else "lookup_failed",
                details=f"Provider returned HTTP error {e.code}: {e.reason}",
                lookup_timestamp=now_iso,
            )
        except Exception as e:
            logger.warning(f"Google Safe Browsing lookup exception: {str(e)}")
            return ThreatIntelligenceMatch(
                provider=self.name,
                status="service_unavailable",
                details=f"Network error or timeout connecting to provider: {str(e)}",
                lookup_timestamp=now_iso,
            )


class PhishTankProvider(ThreatIntelProvider):
    """
    PhishTank URL verification API client.
    Docs: https://phishtank.org/api_info.php
    API key must be provided in PHISHTANK_API_KEY environment variable.
    """
    name = "PhishTank"

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key

    @property
    def api_key(self) -> Optional[str]:
        return self._api_key or os.getenv("PHISHTANK_API_KEY")

    def is_configured(self) -> bool:
        key = self.api_key
        return bool(key and key.strip())

    def lookup_url(self, url: str) -> ThreatIntelligenceMatch:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cache_key = f"phishtank:{url}"
        cached = _get_cached_match(cache_key)
        if cached:
            return cached

        if not self.is_configured():
            return ThreatIntelligenceMatch(
                provider=self.name,
                status="unconfigured",
                details="PhishTank API key (PHISHTANK_API_KEY) is not configured.",
                lookup_timestamp=now_iso,
            )

        endpoint = "https://checkurl.phishtank.com/checkurl/"
        data_params = {
            "url": url,
            "format": "json",
            "app_key": self.api_key,
        }

        try:
            req_data = urllib.parse.urlencode(data_params).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=req_data,
                headers={"User-Agent": "phishtank/cybersentinel-app"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                body = resp.read().decode("utf-8")
                data = json.loads(body)

                results = data.get("results", {})
                in_database = results.get("in_database", False)
                valid = results.get("valid", False)
                phish_detail_page = results.get("phish_detail_page")

                if in_database and valid:
                    match_obj = ThreatIntelligenceMatch(
                        provider=self.name,
                        status="match_detected",
                        threat_type="PHISHING",
                        details="Verified active phishing URL in PhishTank community database.",
                        lookup_timestamp=now_iso,
                        reference_url=phish_detail_page,
                    )
                else:
                    match_obj = ThreatIntelligenceMatch(
                        provider=self.name,
                        status="no_match",
                        details="URL not found or not verified in PhishTank database.",
                        lookup_timestamp=now_iso,
                    )

                _set_cached_match(cache_key, match_obj)
                return match_obj

        except urllib.error.HTTPError as e:
            logger.warning(f"PhishTank HTTP {e.code}: {e.reason}")
            return ThreatIntelligenceMatch(
                provider=self.name,
                status="service_unavailable" if e.code in (429, 500, 502, 503) else "lookup_failed",
                details=f"Provider returned HTTP error {e.code}: {e.reason}",
                lookup_timestamp=now_iso,
            )
        except Exception as e:
            logger.warning(f"PhishTank lookup exception: {str(e)}")
            return ThreatIntelligenceMatch(
                provider=self.name,
                status="service_unavailable",
                details=f"Network error or timeout connecting to provider: {str(e)}",
                lookup_timestamp=now_iso,
            )


class ThreatIntelligenceAggregator:
    """
    Coordinates lookups across configured threat providers with caching and failover.
    """

    def __init__(self, providers: Optional[List[ThreatIntelProvider]] = None):
        self.providers = providers or [
            GoogleSafeBrowsingProvider(),
            PhishTankProvider(),
        ]

    def has_any_configured_provider(self) -> bool:
        return any(p.is_configured() for p in self.providers)

    def evaluate_url(self, url: str) -> List[ThreatIntelligenceMatch]:
        results: List[ThreatIntelligenceMatch] = []
        for provider in self.providers:
            try:
                res = provider.lookup_url(url)
                results.append(res)
            except Exception as e:
                logger.error(f"Unexpected error querying provider {provider.name}: {str(e)}")
                results.append(
                    ThreatIntelligenceMatch(
                        provider=provider.name,
                        status="lookup_failed",
                        details=f"Unexpected client error: {str(e)}",
                        lookup_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    )
                )
        return results
