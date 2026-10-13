"""
Curated CVE Knowledge Catalog for CyberQuant Attacker Agent.
Correlates verified component version strings observed in scanner evidence
with published CVE identifiers. Strictly avoids speculative or invented CVEs.
"""

import re
from typing import Optional, Dict, Any, Tuple


# Curated catalog of well-documented known vulnerabilities for commonly disclosed components.
# Only triggered when exact version evidence matches known vulnerable ranges.
KNOWN_CVE_DATABASE = [
    {
        "component": "Apache",
        "pattern": r"Apache/2\.4\.49",
        "cve_id": "CVE-2021-41773",
        "title": "Apache HTTP Server 2.4.49 Path Traversal & Remote Code Execution",
        "severity": "Critical",
        "cvss": 9.8,
        "impact": "Adversary can map path traversal to arbitrary system files or achieve remote code execution if mod_cgi is enabled.",
        "remediation": "Immediately upgrade Apache HTTP Server to version 2.4.51 or later.",
    },
    {
        "component": "Apache",
        "pattern": r"Apache/2\.4\.50",
        "cve_id": "CVE-2021-42013",
        "title": "Apache HTTP Server 2.4.50 Path Traversal & Remote Code Execution (Incomplete Fix for CVE-2021-41773)",
        "severity": "Critical",
        "cvss": 9.8,
        "impact": "Incomplete fix for CVE-2021-41773 allows path traversal and remote code execution if alias mapping allows or mod_cgi is enabled.",
        "remediation": "Immediately upgrade Apache HTTP Server to version 2.4.51 or later.",
    },
    {
        "component": "Nginx",
        "pattern": r"nginx/1\.(15\.[5-9]|16\.[0-1]|17\.[0-6])",
        "cve_id": "CVE-2019-9511",
        "title": "Nginx HTTP/2 Data Dribble Resource Exhaustion (HTTP/2 Ping Flood)",
        "severity": "High",
        "cvss": 7.5,
        "impact": "Adversary can trigger sustained high CPU and memory denial-of-service via crafted HTTP/2 streams.",
        "remediation": "Upgrade Nginx to version 1.16.1, 1.17.3, or later, or disable HTTP/2 support if unneeded.",
    },
    {
        "component": "PHP",
        "pattern": r"PHP/8\.1\.0-dev",
        "cve_id": "CVE-2021-29472",
        "title": "PHP 8.1.0-dev Backdoor User-Agent Remote Code Execution",
        "severity": "Critical",
        "cvss": 9.8,
        "impact": "Known malicious commit backdoor in PHP 8.1.0-dev allows unauthenticated remote command execution via User-Agent header.",
        "remediation": "Remove PHP 8.1.0-dev immediately and deploy officially signed PHP release builds (>= 8.1.1).",
    },
    {
        "component": "OpenSSL",
        "pattern": r"OpenSSL/1\.0\.1([a-f])?",
        "cve_id": "CVE-2014-0160",
        "title": "OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
        "severity": "High",
        "cvss": 7.5,
        "impact": "Vulnerable OpenSSL heartbeat extension permits unauthorized memory leakage, exposing server private keys and session tokens.",
        "remediation": "Upgrade OpenSSL to version 1.0.1g or later, or modern supported 3.x series.",
    },
    {
        "component": "OpenSSH",
        "pattern": r"OpenSSH_(9\.[0-7]|8\.[5-9])p1",
        "cve_id": "CVE-2024-6387",
        "title": "OpenSSH regreSSHion Signal Handler Race Condition",
        "severity": "High",
        "cvss": 8.1,
        "impact": "Signal handler race condition in sshd can enable unauthenticated remote code execution as root on glibc Linux systems.",
        "remediation": "Upgrade OpenSSH to version 9.8p1 or newer, or set LoginGraceTime 0 in sshd_config as interim workaround.",
    },
]


def match_known_cve(banner: str) -> Optional[Dict[str, Any]]:
    """
    Evaluates observed banner or version strings against the curated CVE database.
    Returns matched vulnerability metadata if and only if reliable version evidence is confirmed.
    """
    if not banner:
        return None

    for entry in KNOWN_CVE_DATABASE:
        if re.search(entry["pattern"], banner, re.IGNORECASE):
            return {
                "cve_id": entry["cve_id"],
                "title": entry["title"],
                "severity": entry["severity"],
                "cvss": entry["cvss"],
                "impact": entry["impact"],
                "remediation": entry["remediation"],
                "matched_pattern": entry["pattern"],
            }

    return None
