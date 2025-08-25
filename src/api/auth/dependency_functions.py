from .cognito import validate_token
from typing import Optional, Dict, Any
from typing import List, Optional
from fastapi import FastAPI, Request, Response, HTTPException, status, Depends, Form
from fastapi.security import OAuth2AuthorizationCodeBearer, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError
from ..api_config import settings
import logging
import time
import requests
from jwt import PyJWKClient, decode as jwt_decode, ExpiredSignatureError, InvalidTokenError

# Configure logging format
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s:\t%(asctime)s %(name)s:%(lineno)d – %(message)s"
)
logger = logging.getLogger(__name__)

# -----------------------------
# Config
# -----------------------------
REGION = settings.COGNITO_REGION
USER_POOL_ID = settings.COGNITO_USER_POOL_ID
CLIENT_ID = settings.COGNITO_APP_PUBLIC_CLIENT_ID

JWKS_URL = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"
jwks_client = PyJWKClient(JWKS_URL)
LEWAY_SECONDS = 60  # allow 60s clock skew


# -----------------------------
# Models
# -----------------------------
class TokenInfo(BaseModel):
    token: str
    auth_method: str
    token_type: str
    sub: str
    cognito_groups: List[str] = ["Free-Tier"]
    email: Optional[str] = None


# -----------------------------
# JWKS cache
# -----------------------------
_jwks_cache = None
_jwks_cache_time = 0
CACHE_TTL = 3600  # 1 hour

def get_jwks(force_refresh: bool = False):
    global _jwks_cache, _jwks_cache_time
    now = time.time()
    if force_refresh or not _jwks_cache or now - _jwks_cache_time > CACHE_TTL:
        resp = requests.get(JWKS_URL)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_cache_time = now
    return _jwks_cache    

# --- Authentication Dependency ---

# authorizationUrl = "https://btap-dev.auth.ca-central-1.amazoncognito.com/oauth2/authorize"
# tokenUrl = "https://btap-dev.auth.ca-central-1.amazoncognito.com/oauth2/token"
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=settings.AUTHORIZATION_URL,
    tokenUrl=settings.TOKEN_URL,
    scopes={"openid": "User Identity"},
    auto_error=False,  # MUST BE FALSE!
)

# HTTP Bearer scheme for manual token input
bearer_scheme = HTTPBearer(auto_error=False)


async def get_api_user(
    request: Request,
    # Try Bearer token first
    bearer_credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    # Fallback: try OAuth2 scheme (used by Swagger UI)
    oauth2_token: Optional[str] = Depends(oauth2_scheme),
) -> Dict[str, Any]:
    """
    Unified dependency for API authentication.
    Supports:
    - Authorization: Bearer <token>
    - Swagger UI OAuth2 flow
    """
    logger.info(" Starting API authentication flow")
    logger.info(f" Request: {request.method} {request.url.path}")
    auth_header = request.headers.get("authorization")
    if auth_header:
        logger.info(f"📎 Found Authorization header: {auth_header[:30]}...")
    else:
        logger.warning("📎 NO Authorization header received!")    
    
    # Log headers (safely, without printing full Authorization)
    headers = dict(request.headers)
    redacted_headers = {
        k: (v[:10] + "...") if k.lower() == "authorization" else v
        for k, v in headers.items()
    }
    logger.debug(f" Request headers: {redacted_headers}")

    token = None
    auth_method = None

    if bearer_credentials:
        token = bearer_credentials.credentials
        auth_method = "bearer_header"
        logger.info(f" Token found in 'Authorization: Bearer' header")
        logger.debug(f" Bearer token preview: {token[:15]}...")
    else:
        logger.info(" No Bearer token found in Authorization header")

    if not token and oauth2_token:
        token = oauth2_token
        auth_method = "oauth2_scheme"
        logger.info(f" Token acquired via OAuth2 scheme (e.g., Swagger UI login)")
        logger.debug(f" OAuth2 token preview: {token[:15]}...")
    elif oauth2_token:
        logger.debug(" OAuth2 token was available but ignored because Bearer header took precedence")
    else:
        logger.warning(" No token from OAuth2 scheme either")

    if not token:
        logger.warning(" Authentication failed: No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Provide Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.info(f" Using token for authentication (method={auth_method})")
    logger.debug(" Validating token with Cognito...")

    try:
        user = await get_current_user_from_token(token)
        logger.info(f" Authentication successful for user: {user.get('email', user.get('sub', 'unknown'))}")
        return user
    except HTTPException as e:
        logger.warning(f" Token validation failed: {e.detail}")
        raise
    except Exception as e:
        logger.error(f" Unexpected error during token validation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user_from_token(token: str) -> Dict[str, Any]:
    """Validate JWT and return user info."""
    try:
        return validate_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token2",
            headers={"WWW-Authenticate": "Bearer"},
        )



async def get_current_user_old(request: Request):
    """Dependency to get the current user from the session cookie."""
    token = request.cookies.get("session_token")
    if not token:
        return None
    try:
        return validate_token(token)
    except HTTPException:
        return None
    
async def get_current_user(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Validate JWT (using your existing validate_token logic)
        claims = validate_token(token)  # Should return decoded claims
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    
    return claims    

async def admin_required(request: Request):
    return True

async def admin_required2(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Validate JWT (should return decoded claims)
        claims = validate_token(token)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    
    # Check role in Cognito groups or other role source
    groups = claims.get("cognito:groups", [])
    if not any(role.lower() == "admin" for role in groups):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    return claims

async def require_user(request: Request):
    """Dependency to get the current user from the session cookie."""
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    return validate_token(token)
    
class TokenInfo(BaseModel):
    token: str
    auth_method: str
    token_type: str

# Custom dependency that handles both authentication methods
async def get_current_token_old(
    oauth2_token: Optional[str] = Depends(oauth2_scheme, use_cache=False),
    bearer_credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme, use_cache=False),
) -> TokenInfo:
    """
    Custom dependency that supports both OAuth2 and Bearer token authentication
    """
    # Try OAuth2 first
    if oauth2_token:
        return TokenInfo(
            token=oauth2_token,
            auth_method="oauth2",
            token_type="Bearer"
        )
    
    # Try Bearer token
    if bearer_credentials:
        return TokenInfo(
            token=bearer_credentials.credentials,
            auth_method="bearer",
            token_type=bearer_credentials.scheme
        )
    
    # No authentication provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated. Provide either OAuth2 token or Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )    

async def get_current_token_311(
    oauth2_token: Optional[str] = Depends(oauth2_scheme),
    bearer_credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> TokenInfo:
    """
    Supports OAuth2 and Bearer authentication.
    Validates against Cognito JWKS with automatic refresh on key rotation.
    """
    raw_token = None
    auth_method = None
    token_type = None

    if oauth2_token:
        raw_token = oauth2_token
        auth_method = "oauth2"
        token_type = "Bearer"
    elif bearer_credentials:
        raw_token = bearer_credentials.credentials
        auth_method = "bearer"
        token_type = bearer_credentials.scheme
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Provide either OAuth2 token or Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Try with cached JWKS
    try:
        claims = jwt.decode(
            raw_token,
            get_jwks(),
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        # Retry once with fresh JWKS (in case of key rotation)
        try:
            claims = jwt.decode(
                raw_token,
                get_jwks(force_refresh=True),
                algorithms=["RS256"],
                audience=CLIENT_ID,
                issuer=ISSUER,
            )
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Return structured TokenInfo
    return TokenInfo(
        token=raw_token,
        auth_method=auth_method,
        token_type=token_type,
        sub=claims.get("sub"),
        cognito_groups=claims.get("cognito:groups", ["Free-Tier"]),
        email=claims.get("email"),
    )

async def get_current_token(
    oauth2_token: Optional[str] = Depends(oauth2_scheme),
    bearer_credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> TokenInfo:
    raw_token = None
    auth_method = None
    token_type = None

    if oauth2_token:
        raw_token = oauth2_token
        auth_method = "oauth2"
        token_type = "Bearer"
    elif bearer_credentials:
        raw_token = bearer_credentials.credentials
        auth_method = "bearer"
        token_type = bearer_credentials.scheme
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Provide either OAuth2 token or Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Detect refresh tokens (not JWTs → no dots)
    if raw_token.count(".") != 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh tokens cannot be used to access this endpoint. Use an ID or Access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Get signing key from Cognito JWKS
        signing_key = jwks_client.get_signing_key_from_jwt(raw_token)

        # Peek at claims (without verifying signature) to detect audience
        unverified_claims = jwt_decode(raw_token, options={"verify_signature": False})
        audience = CLIENT_ID if "aud" in unverified_claims else None

        # Decode and validate claims
        claims = jwt_decode(
            raw_token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=audience,
            leeway=LEWAY_SECONDS,
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenInfo(
        token=raw_token,
        auth_method=auth_method,
        token_type=token_type,
        sub=claims.get("sub"),
        cognito_groups=claims.get("cognito:groups", ["Free-Tier"]),
        email=claims.get("email"),
    )

async def require_user(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    return validate_token(token)