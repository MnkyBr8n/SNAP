# app/mcp/auth.py
"""
JWT authentication and GitHub OAuth for SNAP MCP server.

- JWT creation/validation for both custom and OAuth-issued tokens
- GitHub OAuth login flow (authorize → callback → issue JWT)
- Starlette AuthMiddleware for HTTP+SSE transport
- Disabled by default (SNAP_AUTH_ENABLED=false)
- stdio mode is never affected (no HTTP layer)
"""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import jwt
import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from app.config.settings import get_settings
from app.logging.logger import get_logger

logger = get_logger("mcp.auth")

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_USER_ORGS_URL = "https://api.github.com/user/orgs"


class AuthError(Exception):
    """Raised on authentication failures."""


# =============================================================================
# JWT Helpers
# =============================================================================

def create_jwt(vendor_id: str, extra_claims: Optional[dict] = None) -> str:
    """
    Create a signed JWT token.

    Args:
        vendor_id: Subject identifier (GitHub username or custom vendor_id)
        extra_claims: Optional additional claims to include

    Returns:
        Encoded JWT string
    """
    settings = get_settings()
    auth = settings.auth

    if not auth.jwt_secret:
        raise AuthError("JWT secret not configured (set SNAP_AUTH_JWT_SECRET)")

    now = datetime.now(timezone.utc)
    payload = {
        "sub": vendor_id,
        "iat": now,
        "exp": now + timedelta(hours=auth.jwt_expiry_hours),
        "iss": "snap-mcp",
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, auth.jwt_secret, algorithm=auth.jwt_algorithm)


def decode_jwt(token: str) -> dict:
    """
    Decode and validate a JWT token.

    Args:
        token: Encoded JWT string

    Returns:
        Decoded payload dict

    Raises:
        AuthError: If token is invalid or expired
    """
    settings = get_settings()
    auth = settings.auth

    if not auth.jwt_secret:
        raise AuthError("JWT secret not configured")

    try:
        payload = jwt.decode(
            token,
            auth.jwt_secret,
            algorithms=[auth.jwt_algorithm],
            options={"require": ["sub", "exp", "iat"]},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {e}")


# =============================================================================
# GitHub OAuth Route Handlers
# =============================================================================

async def github_login_redirect(request: Request):
    """Redirect to GitHub OAuth authorization page."""
    settings = get_settings()
    auth = settings.auth

    if not auth.github_client_id:
        return JSONResponse(
            {"error": "GitHub OAuth not configured"},
            status_code=501,
        )

    params = {
        "client_id": auth.github_client_id,
        "scope": "read:org",
    }

    url = f"{GITHUB_AUTHORIZE_URL}?client_id={params['client_id']}&scope={params['scope']}"
    return RedirectResponse(url=url)


async def github_callback(request: Request):
    """
    Handle GitHub OAuth callback.

    Exchanges authorization code for access token, fetches user info,
    optionally checks org membership, then issues a JWT.
    """
    settings = get_settings()
    auth = settings.auth

    code = request.query_params.get("code")
    if not code:
        return JSONResponse(
            {"error": "Missing authorization code"},
            status_code=400,
        )

    if not auth.github_client_id or not auth.github_client_secret:
        return JSONResponse(
            {"error": "GitHub OAuth not configured"},
            status_code=501,
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Exchange code for access token
            token_resp = await client.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id": auth.github_client_id,
                    "client_secret": auth.github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            token_data = token_resp.json()

            if "access_token" not in token_data:
                error = token_data.get("error_description", "Token exchange failed")
                logger.warning("GitHub OAuth token exchange failed", extra={"error": error})
                return JSONResponse(
                    {"error": error},
                    status_code=401,
                )

            access_token = token_data["access_token"]
            gh_headers = {"Authorization": f"Bearer {access_token}"}

            # Fetch GitHub user info
            user_resp = await client.get(GITHUB_USER_URL, headers=gh_headers)
            user_data = user_resp.json()
            github_username = user_data.get("login", "")

            if not github_username:
                return JSONResponse(
                    {"error": "Failed to fetch GitHub user info"},
                    status_code=401,
                )

            # Check org membership if configured
            if auth.github_allowed_orgs:
                orgs_resp = await client.get(GITHUB_USER_ORGS_URL, headers=gh_headers)
                user_orgs = [org.get("login", "").lower() for org in orgs_resp.json()]
                allowed = [o.lower() for o in auth.github_allowed_orgs]

                if not any(org in allowed for org in user_orgs):
                    logger.warning(
                        "GitHub OAuth org check failed",
                        extra={"user": github_username, "user_orgs": user_orgs},
                    )
                    return JSONResponse(
                        {"error": "User not in allowed organizations"},
                        status_code=403,
                    )

        # Issue JWT with GitHub username as vendor_id
        token = create_jwt(
            vendor_id=github_username,
            extra_claims={"auth_method": "github_oauth"},
        )

        logger.info("GitHub OAuth login successful", extra={"user": github_username})

        return JSONResponse({
            "token": token,
            "vendor_id": github_username,
            "auth_method": "github_oauth",
        })

    except httpx.HTTPError as e:
        logger.error(f"GitHub OAuth HTTP error: {e}")
        return JSONResponse(
            {"error": "GitHub OAuth failed"},
            status_code=502,
        )
    except AuthError as e:
        return JSONResponse(
            {"error": str(e)},
            status_code=500,
        )


# =============================================================================
# Custom JWT Token Endpoint
# =============================================================================

async def issue_token(request: Request):
    """
    Issue a JWT token for custom auth (dev/service-to-service).

    POST /auth/token
    Body: {"vendor_id": "my-service"}
    """
    settings = get_settings()

    if not settings.auth.jwt_secret:
        return JSONResponse(
            {"error": "JWT secret not configured (set SNAP_AUTH_JWT_SECRET)"},
            status_code=501,
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Invalid JSON body"},
            status_code=400,
        )

    vendor_id = body.get("vendor_id", "").strip()
    if not vendor_id or len(vendor_id) > 64:
        return JSONResponse(
            {"error": "vendor_id is required (1-64 chars)"},
            status_code=400,
        )

    token = create_jwt(
        vendor_id=vendor_id,
        extra_claims={"auth_method": "custom_jwt"},
    )

    logger.info("Custom JWT issued", extra={"vendor_id": vendor_id})

    return JSONResponse({
        "token": token,
        "vendor_id": vendor_id,
        "auth_method": "custom_jwt",
    })


# =============================================================================
# Auth Middleware
# =============================================================================

# Routes that never require authentication
PUBLIC_PATHS = {"/health", "/auth/github/login", "/auth/github/callback", "/auth/token"}


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware for JWT authentication.

    - Self-disables when auth.enabled == False
    - Skips public paths (/health, /auth/*)
    - Extracts Bearer token from Authorization header
    - Validates JWT and attaches vendor_id to request.state
    """

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        # Auth disabled — pass through
        if not settings.auth.enabled:
            return await call_next(request)

        # Public paths — no auth required
        path = request.url.path.rstrip("/")
        if path in PUBLIC_PATHS or path.startswith("/auth/"):
            return await call_next(request)

        # Extract Bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )

        token = auth_header[7:]  # Strip "Bearer "

        try:
            payload = decode_jwt(token)
            request.state.vendor_id = payload.get("sub", "")
        except AuthError as e:
            logger.warning(f"Auth failed: {e}")
            return JSONResponse(
                {"error": str(e)},
                status_code=401,
            )

        return await call_next(request)
