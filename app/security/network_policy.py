# /app/security/network_policy.py
"""
Purpose: Enforce outbound network allowlist (domains) defined in config settings.

Enhanced with:
- Rate limiting per domain (prevent abuse)
- Request logging (audit trail)
- Private IP blocking (prevent internal network access)
- HTTP timeout configuration
- Content-type validation
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict
from urllib.parse import urlparse
import time
import ipaddress
import threading
import socket

from app.config.settings import get_settings
from app.logging.logger import get_logger

logger = get_logger("security.network_policy")


class NetworkPolicyError(Exception):
    pass


@dataclass(frozen=True)
class AllowedTarget:
    url: str
    hostname: str


# ---------- Rate limiting ----------

class DomainRateLimiter:
    """Thread-safe in-memory rate limiter with bounded memory."""

    MAX_TRACKED_DOMAINS = 1000  # Prevent unbounded memory growth

    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.domain_requests: Dict[str, list] = {}
        self._lock = threading.Lock()

    def check_rate_limit(self, domain: str) -> None:
        """
        Check if domain has exceeded rate limit (thread-safe).

        Args:
            domain: Domain to check

        Raises:
            NetworkPolicyError: If rate limit exceeded
        """
        now = time.time()
        cutoff = now - 60  # Last 60 seconds

        with self._lock:
            # Cleanup stale domains periodically (when at capacity)
            if len(self.domain_requests) >= self.MAX_TRACKED_DOMAINS:
                self._cleanup_stale_domains(cutoff)

            # Initialize or clean old requests
            if domain not in self.domain_requests:
                self.domain_requests[domain] = []

            # Remove requests older than 1 minute
            self.domain_requests[domain] = [
                req_time for req_time in self.domain_requests[domain]
                if req_time > cutoff
            ]

            # Check limit
            if len(self.domain_requests[domain]) >= self.requests_per_minute:
                logger.warning(f"Rate limit exceeded for domain: {domain}")
                raise NetworkPolicyError(
                    f"Rate limit exceeded for domain {domain}: "
                    f"{len(self.domain_requests[domain])} requests in last minute"
                )

            # Record this request
            self.domain_requests[domain].append(now)
            logger.debug(f"Rate limit check passed: {domain} ({len(self.domain_requests[domain])}/{self.requests_per_minute})")

    def _cleanup_stale_domains(self, cutoff: float) -> None:
        """Remove domains with no recent requests (called with lock held)."""
        stale = [d for d, times in self.domain_requests.items()
                 if not times or all(t <= cutoff for t in times)]
        for domain in stale:
            del self.domain_requests[domain]
        if stale:
            logger.debug(f"Cleaned up {len(stale)} stale domains from rate limiter")


# Global rate limiter instance
_rate_limiter = DomainRateLimiter(requests_per_minute=100)


# ---------- Host validation ----------

def _normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def _is_private_ip(hostname: str) -> bool:
    """
    Check if hostname resolves to private IP address.

    Blocks:
    - 127.0.0.0/8 (localhost)
    - 10.0.0.0/8 (private)
    - 172.16.0.0/12 (private)
    - 192.168.0.0/16 (private)
    - 169.254.0.0/16 (link-local)

    Args:
        hostname: Hostname or IP address to check

    Returns:
        True if private IP, False otherwise
    """
    # First check if it's already an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass  # Not an IP, need to resolve

    # Resolve hostname to IP and check
    try:
        resolved_ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in resolved_ips:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    logger.warning(f"Hostname {hostname} resolves to private IP {ip_str}")
                    return True
            except ValueError:
                continue
        return False
    except socket.gaierror:
        # DNS resolution failed - allow (will fail later on actual connection)
        return False


def _is_allowed_host(host: str, allowlist: list[str]) -> bool:
    host = _normalize_host(host)
    if not host:
        return False
    
    # Block private IPs
    if _is_private_ip(host):
        logger.warning(f"Blocked private IP: {host}")
        return False

    for allowed in allowlist:
        allowed = _normalize_host(allowed)
        if not allowed:
            continue

        if host == allowed:
            return True

        # Allow subdomains of allowed domains
        if host.endswith("." + allowed):
            return True

    return False


# ---------- Request logging ----------

def _redact_url_for_log(url: str) -> str:
    """Strip credentials from URL before logging (user:password@ → removed)."""
    try:
        parsed = urlparse(url)
        if parsed.password:
            safe_netloc = parsed.hostname or ""
            if parsed.port:
                safe_netloc += f":{parsed.port}"
            return parsed._replace(netloc=safe_netloc).geturl()
    except (ValueError, AttributeError):
        pass
    return url


def log_outbound_request(
    url: str,
    hostname: str,
    success: bool,
    error: Optional[str] = None
) -> None:
    """
    Log outbound network request for audit trail.

    Args:
        url: Full URL requested (credentials redacted before logging)
        hostname: Hostname extracted from URL
        success: Whether request succeeded
        error: Error message if failed
    """
    logger.info("Outbound request", extra={
        "url": _redact_url_for_log(url),
        "hostname": hostname,
        "success": success,
        "error": error
    })


# ---------- URL validation ----------

def validate_outbound_url(url: str) -> AllowedTarget:
    """
    Validate a URL against the configured outbound allowlist.
    
    Enforces:
    - Outbound network enabled
    - HTTP/HTTPS only
    - Domain in allowlist
    - Not private IP
    - Rate limiting
    
    Returns:
        AllowedTarget if allowed
    
    Raises:
        NetworkPolicyError: If validation fails
    """
    settings = get_settings()

    if not settings.network.outbound_enabled:
        log_outbound_request(url, "", False, "Outbound network disabled")
        raise NetworkPolicyError("Outbound network is disabled")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        log_outbound_request(url, "", False, "Invalid scheme")
        raise NetworkPolicyError("Only http/https outbound URLs are permitted")

    host = _normalize_host(parsed.hostname or "")
    
    # Check rate limit
    try:
        _rate_limiter.check_rate_limit(host)
    except NetworkPolicyError as e:
        log_outbound_request(url, host, False, str(e))
        raise
    
    # Check allowlist
    if not _is_allowed_host(host, settings.network.domain_allowlist):
        log_outbound_request(url, host, False, "Not in allowlist")
        raise NetworkPolicyError("Outbound target not in allowlist")

    log_outbound_request(url, host, True)
    return AllowedTarget(url=url, hostname=host)


def validate_git_remote(remote: str) -> str:
    """
    Validate an HTTPS git remote (or git@ style) against the allowlist.
    
    Enforces:
    - Outbound network enabled
    - HTTP/HTTPS or git@ format
    - Domain in allowlist
    - Not private IP
    - Rate limiting
    
    Returns:
        Remote string if allowed
    
    Raises:
        NetworkPolicyError: If validation fails
    """
    settings = get_settings()

    if not settings.network.outbound_enabled:
        raise NetworkPolicyError("Outbound network is disabled")

    remote = (remote or "").strip()
    if not remote:
        raise NetworkPolicyError("Empty git remote")

    host: Optional[str] = None

    # https://github.com/org/repo.git
    if remote.startswith("http://") or remote.startswith("https://"):
        parsed = urlparse(remote)
        if parsed.scheme not in {"http", "https"}:
            raise NetworkPolicyError("Only http/https git remotes are permitted")
        host = parsed.hostname

    # git@github.com:org/repo.git
    elif remote.startswith("git@"):
        try:
            after_at = remote.split("@", 1)[1]
            host = after_at.split(":", 1)[0]
        except Exception as exc:
            raise NetworkPolicyError("Invalid git@ remote format") from exc

    else:
        raise NetworkPolicyError("Unsupported git remote format")

    host = _normalize_host(host or "")
    
    # Check rate limit
    _rate_limiter.check_rate_limit(host)
    
    # Check allowlist
    if not _is_allowed_host(host, settings.network.domain_allowlist):
        log_outbound_request(remote, host, False, "Git remote not in allowlist")
        raise NetworkPolicyError("Git remote host not in allowlist")

    log_outbound_request(remote, host, True)
    return remote


# ---------- Content validation ----------

def validate_response_content_type(
    content_type: Optional[str],
    expected_types: list[str]
) -> None:
    """
    Validate HTTP response content-type header.
    
    Args:
        content_type: Content-Type header value
        expected_types: List of expected content types (e.g., ['text/html', 'application/json'])
    
    Raises:
        NetworkPolicyError: If content type not in expected list
    """
    if not content_type:
        logger.warning("No Content-Type header in response")
        return
    
    # Normalize (remove charset, etc.)
    content_type_normalized = content_type.split(";")[0].strip().lower()
    
    if content_type_normalized not in expected_types:
        logger.warning(f"Unexpected content type: {content_type_normalized}")
        raise NetworkPolicyError(
            f"Unexpected content type: {content_type_normalized} "
            f"(expected one of: {expected_types})"
        )


def get_http_timeout() -> int:
    """
    Get HTTP request timeout from settings.
    
    Returns:
        Timeout in seconds
    """
    settings = get_settings()
    # Default to 30 seconds if not configured
    return getattr(settings, 'http_request_timeout_seconds', 30)