"""
Impersonation and Brand Deception Analyzer for CyberSentinal.
Analyzes domain structures, homoglyphs, typosquatting, Punycode, redirect anomalies,
and credential harvest indicators against known official brands.
Does NOT accuse sites of fraud without clear evidence, and never conflates
technical header misconfigurations with scam behavior.
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple

from app.schemas.trust import ImpersonationSignal

# Verified Catalog of High-Value Brands and Their Canonical Official Domains
# Can be extended via configuration or runtime rules
KNOWN_BRANDS_CATALOG: Dict[str, Dict[str, Any]] = {
    "google": {
        "display_name": "Google",
        "official_domains": ["google.com", "google.co.in", "google.co.uk", "google.de", "google.fr", "googleapis.com", "gstatic.com"],
        "keywords": ["google", "gmail", "googledrive"],
    },
    "microsoft": {
        "display_name": "Microsoft",
        "official_domains": ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "azure.com", "microsoftonline.com"],
        "keywords": ["microsoft", "office365", "outlook", "onedrive", "azure"],
    },
    "apple": {
        "display_name": "Apple",
        "official_domains": ["apple.com", "icloud.com"],
        "keywords": ["apple", "icloud", "appleid"],
    },
    "amazon": {
        "display_name": "Amazon",
        "official_domains": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "aws.amazon.com"],
        "keywords": ["amazon", "amazonseller", "aws"],
    },
    "paypal": {
        "display_name": "PayPal",
        "official_domains": ["paypal.com", "paypal.me"],
        "keywords": ["paypal"],
    },
    "facebook": {
        "display_name": "Meta / Facebook",
        "official_domains": ["facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"],
        "keywords": ["facebook", "meta", "instagram", "whatsapp"],
    },
    "netflix": {
        "display_name": "Netflix",
        "official_domains": ["netflix.com"],
        "keywords": ["netflix"],
    },
    "chase": {
        "display_name": "Chase Bank",
        "official_domains": ["chase.com", "jpmorganchase.com"],
        "keywords": ["chase", "chasebank"],
    },
    "bankofamerica": {
        "display_name": "Bank of America",
        "official_domains": ["bankofamerica.com", "bofa.com"],
        "keywords": ["bankofamerica", "bofa"],
    },
    "wellsfargo": {
        "display_name": "Wells Fargo",
        "official_domains": ["wellsfargo.com"],
        "keywords": ["wellsfargo"],
    },
    "github": {
        "display_name": "GitHub",
        "official_domains": ["github.com", "github.io"],
        "keywords": ["github"],
    },
    "binance": {
        "display_name": "Binance",
        "official_domains": ["binance.com"],
        "keywords": ["binance"],
    },
    "coinbase": {
        "display_name": "Coinbase",
        "official_domains": ["coinbase.com"],
        "keywords": ["coinbase"],
    },
}

# Common Latin-Cyrillic-Greek homoglyphs
HOMOGLYPH_SUBSTITUTIONS = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    '0': 'o', '1': 'l', '3': 'e', '5': 's',
}


def extract_base_domain(hostname: str) -> str:
    """Extracts base registration domain (e.g. 'sub.login.example.com' -> 'example.com')."""
    clean_host = hostname.lower().strip(".")
    parts = clean_host.split(".")
    if len(parts) <= 2:
        return clean_host

    # Handle known 2-part ccTLDs e.g. co.uk, com.au, co.in
    two_part_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "net.in", "com.au", "net.au", "com.br", "co.jp"}
    joined_last_two = f"{parts[-2]}.{parts[-1]}"
    if joined_last_two in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{joined_last_two}"

    return f"{parts[-2]}.{parts[-1]}"


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_punycode_and_homoglyphs(domain: str) -> Optional[ImpersonationSignal]:
    """Detects Internationalized Domain Names (IDN/Punycode 'xn--') and lookalike homoglyphs."""
    lower_domain = domain.lower()
    if "xn--" in lower_domain:
        try:
            decoded = lower_domain.encode("utf-8").decode("idna")
            # Check if decoded contains non-ASCII characters that mimic Latin
            has_non_ascii = any(ord(char) > 127 for char in decoded)
            if has_non_ascii:
                return ImpersonationSignal(
                    signal_type="punycode",
                    severity="High",
                    description=f"Punycode encoded domain ({lower_domain}) resolves to Unicode '{decoded}', often used to visually mimic trusted brands.",
                    evidence={"raw_domain": lower_domain, "decoded_unicode": decoded},
                )
        except Exception:
            return ImpersonationSignal(
                signal_type="punycode",
                severity="Medium",
                description=f"Domain contains Punycode prefix 'xn--', requiring careful visual inspection.",
                evidence={"raw_domain": lower_domain},
            )

    # Check for homoglyph substitution characters inside ASCII/Unicode mix
    for char, target in HOMOGLYPH_SUBSTITUTIONS.items():
        if char in domain and ord(char) > 127:
            return ImpersonationSignal(
                signal_type="homoglyph",
                severity="High",
                description=f"Domain contains Unicode homoglyph '{char}' that resembles ASCII '{target}'.",
                evidence={"matched_character": char, "resembles_ascii": target, "domain": domain},
            )

    return None


def detect_brand_typosquatting_and_keywords(
    domain: str,
    base_domain: str,
) -> List[ImpersonationSignal]:
    """
    Checks if domain incorporates recognized brand names or typosquats
    without belonging to the verified official domain owner.
    """
    signals: List[ImpersonationSignal] = []
    clean_base = base_domain.lower()
    clean_full = domain.lower()
    base_name = clean_base.split(".")[0]

    for brand_key, brand_info in KNOWN_BRANDS_CATALOG.items():
        official_domains = brand_info["official_domains"]

        # If domain IS legitimately one of the official domains, it is NOT an impersonator!
        is_official = any(clean_full == off or clean_full.endswith(f".{off}") for off in official_domains)
        if is_official:
            continue

        # Signal 1: Typosquatting on official domain name (e.g., 'g00gle.com', 'paypa1.com', 'amzon.com')
        for off_dom in official_domains:
            off_base_name = off_dom.split(".")[0]
            if len(off_base_name) >= 4 and len(base_name) >= 4:
                dist = levenshtein_distance(base_name, off_base_name)
                # Distance of 1 (single typo) or distance of 2 on longer names
                if dist == 1 or (dist == 2 and len(off_base_name) >= 7):
                    signals.append(
                        ImpersonationSignal(
                            signal_type="typosquatting",
                            severity="High",
                            target_brand=brand_info["display_name"],
                            official_domain=official_domains[0],
                            description=(
                                f"Domain '{clean_base}' is suspiciously similar (edit distance {dist}) "
                                f"to official {brand_info['display_name']} domain '{off_dom}'."
                            ),
                            evidence={
                                "domain": clean_base,
                                "official_target": off_dom,
                                "levenshtein_distance": dist,
                            },
                        )
                    )
                    break

        # Signal 2: Brand keyword embedded in untrusted domain or subdomain
        # e.g., 'paypal-security-update.com' or 'login.paypal.attacker.com'
        for kw in brand_info["keywords"]:
            # Case A: Brand name in subdomain of an unrelated domain (e.g. paypal.com.verify-user.net)
            if f"{kw}." in clean_full and clean_base not in official_domains:
                signals.append(
                    ImpersonationSignal(
                        signal_type="brand_name_in_subdomain",
                        severity="High",
                        target_brand=brand_info["display_name"],
                        official_domain=official_domains[0],
                        description=(
                            f"Host '{clean_full}' places brand keyword '{kw}' in a subdomain or prefix "
                            f"on external base domain '{clean_base}', a common deception technique."
                        ),
                        evidence={"full_host": clean_full, "base_domain": clean_base, "keyword": kw},
                    )
                )
                break
            # Case B: Brand name compounded with security/login/verify hyphens
            # e.g. 'paypal-login-alert.com'
            elif re.search(rf"\b{kw}[-_]|[-_]{kw}\b", base_name):
                signals.append(
                    ImpersonationSignal(
                        signal_type="brand_name_in_subdomain",
                        severity="High",
                        target_brand=brand_info["display_name"],
                        official_domain=official_domains[0],
                        description=(
                            f"Domain '{clean_base}' embeds brand name '{kw}' with descriptive keywords "
                            f"outside official {brand_info['display_name']} ownership."
                        ),
                        evidence={"domain": clean_base, "keyword": kw, "official_domain": official_domains[0]},
                    )
                )
                break

    return signals


def detect_credential_harvesting_signals(
    domain: str,
    base_domain: str,
    page_title: Optional[str] = None,
    forms: Optional[List[Dict[str, Any]]] = None,
    impersonation_signals: Optional[List[ImpersonationSignal]] = None,
) -> Optional[ImpersonationSignal]:
    """
    Evaluates whether page content or forms collect credentials/passwords
    while impersonation signals are active on an unofficial domain.
    """
    has_impersonation = bool(impersonation_signals and len(impersonation_signals) > 0)
    if not has_impersonation:
        return None

    # Check for password inputs or login indicators
    has_password_input = False
    if forms:
        for f in forms:
            inputs = f.get("inputs", [])
            for inp in inputs:
                inp_type = str(inp.get("type", "")).lower()
                inp_name = str(inp.get("name", "")).lower()
                if inp_type == "password" or "pass" in inp_name or "pwd" in inp_name:
                    has_password_input = True
                    break
            if has_password_input:
                break

    # Check title for login/signin claims
    title_lower = (page_title or "").lower()
    login_keywords = ["sign in", "log in", "login", "authenticate", "verify account", "enter password"]
    has_login_title = any(kw in title_lower for kw in login_keywords)

    if has_password_input or has_login_title:
        primary_brand = impersonation_signals[0].target_brand or "Recognized Brand"
        return ImpersonationSignal(
            signal_type="copied_branding_with_credentials",
            severity="High",
            target_brand=primary_brand,
            description=(
                f"Page on unofficial domain '{base_domain}' presents login/credential input elements "
                f"while displaying signs of {primary_brand} brand impersonation."
            ),
            evidence={
                "has_password_input": has_password_input,
                "has_login_title": has_login_title,
                "page_title": page_title,
                "domain": base_domain,
            },
        )

    return None


def analyze_impersonation_risks(
    target_url: str,
    final_url: Optional[str] = None,
    redirect_chain: Optional[List[Dict[str, Any]]] = None,
    page_title: Optional[str] = None,
    forms: Optional[List[Dict[str, Any]]] = None,
) -> List[ImpersonationSignal]:
    """
    Comprehensive, explainable impersonation analysis.
    Evaluates Punycode, homoglyphs, typosquatting, unauthorized brand names,
    redirect anomalies, and credential harvesting on unofficial domains.
    """
    signals: List[ImpersonationSignal] = []

    parsed_target = urllib.parse.urlsplit(target_url if "://" in target_url else f"https://{target_url}")
    target_host = (parsed_target.hostname or "").lower().strip(".")
    if not target_host:
        return signals

    base_domain = extract_base_domain(target_host)

    # 1. Punycode & homoglyphs
    p_signal = detect_punycode_and_homoglyphs(target_host)
    if p_signal:
        signals.append(p_signal)

    # 2. Typosquatting and brand keywords
    b_signals = detect_brand_typosquatting_and_keywords(target_host, base_domain)
    signals.extend(b_signals)

    # 3. Redirect chain anomaly (e.g. requested A, but unexpectedly redirected to totally different external domain)
    if final_url and redirect_chain and len(redirect_chain) > 0:
        parsed_final = urllib.parse.urlsplit(final_url)
        final_host = (parsed_final.hostname or "").lower().strip(".")
        if final_host:
            final_base = extract_base_domain(final_host)
            if base_domain != final_base:
                signals.append(
                    ImpersonationSignal(
                        signal_type="suspicious_redirect",
                        severity="Medium",
                        description=(
                            f"Target initially requested at '{target_host}' redirected across different base domains "
                            f"to '{final_host}', which may indicate redirection masking or cloaking."
                        ),
                        evidence={
                            "initial_host": target_host,
                            "final_host": final_host,
                            "redirect_hops": len(redirect_chain),
                        },
                    )
                )

    # 4. Credential harvesting on lookalike/impersonating site
    cred_signal = detect_credential_harvesting_signals(
        target_host, base_domain, page_title, forms, signals
    )
    if cred_signal:
        signals.append(cred_signal)

    return signals
