"""
SSRF Protection and URL Normalization Guard for CyberQuant Attacker Agent.
Enforces strict boundary isolation against private networks, localhost,
link-local, cloud metadata services, and DNS-rebinding attacks.
"""

import ipaddress
import os
import socket
import urllib.parse
from typing import Tuple, List, Optional, Dict, Any


class SSRFProtectionError(ValueError):
    """Raised when a URL or resolved destination violates SSRF safety boundaries."""
    pass


class TargetAuthorizationError(ValueError):
    """Raised when target authorization criteria are not met."""
    pass


def get_local_dev_target_config() -> Optional[Dict[str, Any]]:
    """
    Retrieves the explicitly configured local development test target.
    Opt-in only: requires ALLOW_LOCAL_DEV_SCAN=true AND CYBERSENTINEL_ENV in ('development', 'test', 'local').
    The target must match LOCAL_DEV_TARGET (default: 'http://localhost:4000').
    Returns dict with (scheme, host, port, normalized_target) or None if disabled.
    """
    allow_flag = os.getenv("ALLOW_LOCAL_DEV_SCAN", "").strip().lower()
    env_name = os.getenv("CYBERSENTINEL_ENV", os.getenv("ENVIRONMENT", "production")).strip().lower()

    if allow_flag not in ("true", "1", "yes") or env_name not in ("development", "test", "local"):
        return None

    raw_target = os.getenv("LOCAL_DEV_TARGET", "http://localhost:4000").strip()
    if not raw_target:
        return None

    try:
        parsed = urllib.parse.urlsplit(raw_target if "://" in raw_target else f"http://{raw_target}")
        scheme = parsed.scheme.lower() or "http"
        host = (parsed.hostname or "localhost").lower().strip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
        return {
            "scheme": scheme,
            "host": host,
            "port": port,
            "origin": f"{scheme}://{host}:{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else f"{scheme}://{host}",
        }
    except Exception:
        return None


# Disallowed domain suffixes and reserved names
BLOCKED_HOSTNAMES = {
    "localhost",
    "loopback",
    "metadata",
    "metadata.google.internal",
    "instance-data",
}

BLOCKED_HOSTNAME_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
)

# Explicit IPv4 and IPv6 forbidden networks
FORBIDDEN_NETWORKS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC1918
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address / Carrier NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC1918
    ipaddress.ip_network("198.18.0.0/15"),      # Network Benchmark Tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
]


def is_ip_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Evaluates whether an IP address belongs to loopback, private, link-local,
    multicast, reserved, or cloud-metadata address spaces.
    Handles IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1).
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True

    for net in FORBIDDEN_NETWORKS:
        if ip in net:
            return True

    return False


def normalize_target_url(raw_url: str) -> Tuple[str, str, int, str]:
    """
    Validates and normalizes target URL.
    Returns (normalized_url, hostname, port, path_with_query).
    Raises SSRFProtectionError on unsafe formatting, unapproved schemes, or prohibited destinations.
    In development mode with ALLOW_LOCAL_DEV_SCAN=true, permits ONLY the single configured
    LOCAL_DEV_TARGET (e.g. localhost:4000). All other private/loopback/internal targets remain strictly blocked.
    """
    clean_url = raw_url.strip()
    if not clean_url:
        raise SSRFProtectionError("Target URL cannot be empty.")

    parsed = urllib.parse.urlsplit(clean_url)

    # If scheme was omitted (e.g. "example.com/path"), default to https
    if not parsed.scheme:
        clean_url = f"https://{clean_url}"
        parsed = urllib.parse.urlsplit(clean_url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFProtectionError(f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    if not parsed.hostname:
        raise SSRFProtectionError("Invalid URL: missing target hostname.")

    # Disallow embedded user credentials (e.g., http://admin:pass@host)
    if parsed.username or parsed.password:
        raise SSRFProtectionError("User authentication credentials in URL are prohibited.")

    hostname = parsed.hostname.lower().strip(".")
    if not hostname:
        raise SSRFProtectionError("Invalid URL hostname.")

    # Determine port
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80

    if port < 1 or port > 65535:
        raise SSRFProtectionError(f"Invalid port '{port}'. Must be between 1 and 65535.")

    # Check whether an opt-in local dev test target is active and matches
    local_dev_cfg = get_local_dev_target_config()
    is_authorized_local_test_target = False
    if local_dev_cfg is not None:
        cfg_host = local_dev_cfg["host"]
        cfg_port = local_dev_cfg["port"]
        cfg_scheme = local_dev_cfg["scheme"]
        # Exact match required for configured host and port
        if hostname == cfg_host and port == cfg_port:
            if parsed.scheme.lower() == cfg_scheme:
                is_authorized_local_test_target = True

    if not is_authorized_local_test_target:
        # Check blocked hostnames and suffixes
        if hostname in BLOCKED_HOSTNAMES:
            raise SSRFProtectionError(
                f"Target host '{hostname}' is a prohibited loopback/internal destination. "
                "Local testing requires enabling developer opt-in mode with ALLOW_LOCAL_DEV_SCAN=true."
            )

        for suffix in BLOCKED_HOSTNAME_SUFFIXES:
            if hostname.endswith(suffix):
                raise SSRFProtectionError(
                    f"Target host '{hostname}' belongs to prohibited internal domain suffix '{suffix}'."
                )

        # If hostname is an IP literal, validate immediately
        try:
            ip_obj = ipaddress.ip_address(hostname)
        except ValueError:
            ip_obj = None

        if ip_obj is not None and is_ip_forbidden(ip_obj):
            raise SSRFProtectionError(
                f"Target host '{hostname}' is in a prohibited private, loopback, or metadata IP range."
            )

    path_with_query = parsed.path or "/"
    if parsed.query:
        path_with_query += f"?{parsed.query}"

    normalized_url = f"{parsed.scheme.lower()}://{hostname}"
    if (parsed.scheme.lower() == "http" and port != 80) or (parsed.scheme.lower() == "https" and port != 443):
        normalized_url += f":{port}"
    normalized_url += path_with_query

    return normalized_url, hostname, port, path_with_query


import concurrent.futures

DEFAULT_DNS_TIMEOUT_SECONDS = 3.0
MAX_DNS_RESOLVER_WORKERS = 4

# Bounded static executor for DNS resolution to guarantee thread accumulation bounds.
_DNS_RESOLVER_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_DNS_RESOLVER_WORKERS,
    thread_name_prefix="ssrf-dns-resolver"
)


def resolve_and_verify_ip(
    hostname: str,
    port: int,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT_SECONDS,
) -> Tuple[str, socket.AddressFamily]:
    """
    Performs bounded DNS resolution and validates every resolved IP against forbidden ranges.
    Returns (verified_ip_str, address_family) to pin the exact socket connection,
    defeating DNS rebinding attacks.

    If opt-in local dev mode is active and the target strictly matches LOCAL_DEV_TARGET,
    resolutions to loopback (127.0.0.1 or ::1) for that specific target host and port are accepted.
    Any resolution to other private networks (10.x, 192.168.x, 172.16.x) or cloud metadata (169.254.x)
    is strictly rejected.
    """
    local_dev_cfg = get_local_dev_target_config()
    is_authorized_local_test_target = False
    if local_dev_cfg is not None:
        if hostname.lower().strip(".") == local_dev_cfg["host"] and port == local_dev_cfg["port"]:
            is_authorized_local_test_target = True

    # 1. If hostname is directly an IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_authorized_local_test_target and ip_obj.is_loopback:
            family = socket.AF_INET6 if isinstance(ip_obj, ipaddress.IPv6Address) else socket.AF_INET
            return str(ip_obj), family

        if is_ip_forbidden(ip_obj):
            raise SSRFProtectionError(f"Destination IP '{hostname}' is in a prohibited private or reserved range.")
        family = socket.AF_INET6 if isinstance(ip_obj, ipaddress.IPv6Address) else socket.AF_INET
        return str(ip_obj), family
    except ValueError:
        # Not a raw IP literal; proceed to DNS resolution
        pass

    # 2. Resolve via socket.getaddrinfo in bounded executor
    def _perform_lookup():
        return socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )

    future = _DNS_RESOLVER_POOL.submit(_perform_lookup)
    try:
        addr_infos = future.result(timeout=dns_timeout)
    except concurrent.futures.TimeoutError:
        raise SSRFProtectionError(
            f"DNS resolution for '{hostname}' timed out after {dns_timeout:.1f}s deadline."
        )
    except socket.gaierror as e:
        raise SSRFProtectionError(f"DNS resolution failed for '{hostname}': {str(e)}")
    except Exception as e:
        raise SSRFProtectionError(f"DNS lookup error for '{hostname}': {str(e)}")

    if not addr_infos:
        raise SSRFProtectionError(f"No IP addresses resolved for hostname '{hostname}'.")

    verified_ips: List[Tuple[str, socket.AddressFamily]] = []

    # Check EVERY resolved IP
    for family, socktype, proto, canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFProtectionError(f"Invalid IP address format returned by DNS: '{ip_str}'.")

        if is_authorized_local_test_target:
            # Under local dev mode, allow ONLY loopback address space (127.0.0.0/8 or ::1)
            # Never allow RFC1918 internal networks (10.x, 192.168.x), carrier NAT, or cloud metadata
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                mapped = ip_obj.ipv4_mapped
                if not mapped.is_loopback:
                    raise SSRFProtectionError(
                        f"Local dev scan target '{hostname}' resolved to non-loopback prohibited address '{ip_str}'."
                    )
            elif not ip_obj.is_loopback:
                raise SSRFProtectionError(
                    f"Local dev scan target '{hostname}' resolved to non-loopback prohibited address '{ip_str}'."
                )
        else:
            if is_ip_forbidden(ip_obj):
                raise SSRFProtectionError(
                    f"DNS resolution for '{hostname}' returned prohibited address '{ip_str}' (private/loopback/cloud-metadata)."
                )

        verified_ips.append((ip_str, family))

    if not verified_ips:
        raise SSRFProtectionError(f"Could not verify a secure address for '{hostname}'.")

    # Return the first securely verified IP
    return verified_ips[0]


def validate_destination_url(url: str) -> Tuple[bool, str]:
    """
    Validates an arbitrary outbound URL (e.g. from browser subresource or navigation).
    Returns (True, reason) if safe, or (False, rejection_reason) if it violates SSRF rules.
    Disallows data:, file:, gopher:, ftp:, loopback, private ranges, and non-configured local hosts.
    """
    try:
        parsed = urllib.parse.urlsplit(url.strip())
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return False, f"Prohibited scheme '{scheme}'"

        if not parsed.hostname:
            return False, "Missing hostname"

        hostname = parsed.hostname.lower().strip(".")
        port = parsed.port or (443 if scheme == "https" else 80)

        # Check local dev configuration
        local_dev_cfg = get_local_dev_target_config()
        if local_dev_cfg is not None:
            if hostname == local_dev_cfg["host"] and port == local_dev_cfg["port"]:
                return True, "Authorized local dev target"

        # Check standard allowed ports for public targets
        if port not in (80, 443, 8080, 8443):
            return False, f"Forbidden port '{port}' for public web scanning."

        # Check blocked hostnames and suffixes
        if hostname in BLOCKED_HOSTNAMES:
            return False, f"Target host '{hostname}' is a prohibited loopback/internal destination."

        for suffix in BLOCKED_HOSTNAME_SUFFIXES:
            if hostname.endswith(suffix):
                return False, f"Target host '{hostname}' belongs to prohibited internal domain suffix '{suffix}'."

        # If IP literal, check immediately
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if is_ip_forbidden(ip_obj):
                return False, f"Target IP '{hostname}' is in a prohibited private or metadata range."
        except ValueError:
            pass

        # Resolve IP to verify no DNS rebinding or private resolution
        try:
            resolve_and_verify_ip(hostname, port)
        except SSRFProtectionError as e:
            return False, str(e)

        return True, "Safe destination"
    except Exception as e:
        return False, str(e)

