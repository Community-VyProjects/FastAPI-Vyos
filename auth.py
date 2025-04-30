from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import RedirectResponse
from jose import jwt, JWTError
import httpx
from typing import Dict, Optional, List, Any
import os
from pydantic import BaseModel
from dotenv import load_dotenv
import time
from urllib.parse import urlencode

# Load environment variables
load_dotenv()

# OIDC Configuration
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL", "")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "http://localhost:3001/auth/callback")
OIDC_LOGOUT_REDIRECT_URI = os.getenv("OIDC_LOGOUT_REDIRECT_URI", "http://localhost:3001")
OIDC_SCOPES = os.getenv("OIDC_SCOPES", "openid email profile").split()
OIDC_USER_ROLES = os.getenv("OIDC_USER_ROLES", "").split(",")
OIDC_ADMIN_ROLES = os.getenv("OIDC_ADMIN_ROLES", "").split(",")
JWT_SECRET = os.getenv("JWT_SECRET", "secret")

# Check if OIDC is enabled
OIDC_ENABLED = all([OIDC_DISCOVERY_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET])

# OIDC Metadata cache
oidc_metadata = {}
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="",  # Will be populated dynamically
    tokenUrl="",  # Will be populated dynamically
    scopes={"openid": "OpenID Connect"},
    auto_error=False,
)

# Pydantic models
class TokenData(BaseModel):
    sub: str
    email: Optional[str] = None
    name: Optional[str] = None
    roles: List[str] = []
    exp: Optional[int] = None

class User(BaseModel):
    id: str
    email: Optional[str] = None
    name: Optional[str] = None
    roles: List[str] = []
    is_admin: bool = False

async def get_oidc_metadata() -> Dict[str, Any]:
    """Fetch OIDC provider metadata from discovery URL"""
    global oidc_metadata
    
    if not OIDC_DISCOVERY_URL:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="OIDC is not configured"
        )
    
    if not oidc_metadata:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(OIDC_DISCOVERY_URL)
                response.raise_for_status()
                oidc_metadata = response.json()
                
                # Update OAuth2 scheme URLs
                oauth2_scheme.authorizationUrl = oidc_metadata.get("authorization_endpoint", "")
                oauth2_scheme.tokenUrl = oidc_metadata.get("token_endpoint", "")
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to fetch OIDC metadata: {str(e)}"
            )
    
    return oidc_metadata

async def get_login_url(request: Request) -> str:
    """Get OIDC login URL with all required parameters"""
    if not OIDC_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="OIDC is not configured"
        )
    
    metadata = await get_oidc_metadata()
    auth_endpoint = metadata.get("authorization_endpoint")
    
    if not auth_endpoint:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization endpoint not found in OIDC metadata"
        )
    
    # Generate random state
    from secrets import token_urlsafe
    state = token_urlsafe(32)
    
    # Store state in session or use a state parameter in the return URL
    request.session["oidc_state"] = state
    
    params = {
        "client_id": OIDC_CLIENT_ID,
        "response_type": "code",
        "scope": " ".join(OIDC_SCOPES),
        "redirect_uri": OIDC_REDIRECT_URI,
        "state": state,
    }
    
    return f"{auth_endpoint}?{urlencode(params)}"

async def exchange_code_for_token(code: str) -> Dict[str, Any]:
    """Exchange authorization code for tokens"""
    metadata = await get_oidc_metadata()
    token_endpoint = metadata.get("token_endpoint")
    
    if not token_endpoint:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token endpoint not found in OIDC metadata"
        )
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": OIDC_REDIRECT_URI,
                    "client_id": OIDC_CLIENT_ID,
                    "client_secret": OIDC_CLIENT_SECRET,
                },
            )
            response.raise_for_status()
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to exchange code for token: {str(e)}"
        )

async def validate_token(token: str) -> Dict[str, Any]:
    """Validate ID token and extract user information"""
    metadata = await get_oidc_metadata()
    jwks_uri = metadata.get("jwks_uri")
    issuer = metadata.get("issuer")
    
    if not jwks_uri or not issuer:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWKS URI or issuer not found in OIDC metadata"
        )
    
    try:
        # Fetch JWKS
        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            jwks = response.json()
        
        # Decode the token without verification to get the key ID
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        
        # Find the matching key in JWKS
        key = None
        for jwk in jwks.get("keys", []):
            if jwk.get("kid") == kid:
                key = jwk
                break
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: Key not found"
            )
        
        # Verify and decode the token
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=OIDC_CLIENT_ID,
            issuer=issuer,
        )
        
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )

def get_token_from_cookie(request: Request) -> Optional[str]:
    """Extract access token from cookies"""
    return request.cookies.get("access_token")

async def create_session_cookie(id_token: str, access_token: str, expires_in: int) -> Dict[str, str]:
    """Create session cookie with tokens"""
    expiration = time.time() + expires_in
    
    # Decode token to get user info
    try:
        # For simplicity, we're not fully validating here since we just got it
        payload = jwt.decode(id_token, options={"verify_signature": False})
        
        # Create session token
        session_data = {
            "sub": payload.get("sub"),
            "email": payload.get("email"),
            "name": payload.get("name", payload.get("preferred_username")),
            "roles": payload.get("roles", []),
            "exp": int(expiration),
        }
        
        session_token = jwt.encode(session_data, JWT_SECRET, algorithm="HS256")
        
        return {
            "session_token": session_token,
            "access_token": access_token,
            "id_token": id_token,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to create session: {str(e)}"
        )

async def get_logout_url(id_token: Optional[str] = None) -> str:
    """Get OIDC logout URL"""
    if not OIDC_ENABLED:
        return "/"
    
    metadata = await get_oidc_metadata()
    end_session_endpoint = metadata.get("end_session_endpoint")
    
    if not end_session_endpoint:
        # If provider doesn't support logout, just return to home
        return "/"
    
    params = {
        "client_id": OIDC_CLIENT_ID,
        "post_logout_redirect_uri": OIDC_LOGOUT_REDIRECT_URI,
    }
    
    if id_token:
        params["id_token_hint"] = id_token
    
    return f"{end_session_endpoint}?{urlencode(params)}"

async def get_current_user(request: Request) -> Optional[User]:
    """Get current user from session cookie"""
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        return None
    
    try:
        payload = jwt.decode(session_token, JWT_SECRET, algorithms=["HS256"])
        token_data = TokenData(**payload)
        
        # Check if token is expired
        if token_data.exp and token_data.exp < time.time():
            return None
        
        # Create user object
        user = User(
            id=token_data.sub,
            email=token_data.email,
            name=token_data.name,
            roles=token_data.roles,
            is_admin=any(role in OIDC_ADMIN_ROLES for role in token_data.roles)
        )
        
        return user
    except JWTError:
        return None
    except Exception:
        return None

def require_auth(request: Request) -> User:
    """Dependency to require authentication"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return user

def require_admin(request: Request) -> User:
    """Dependency to require admin role"""
    user = get_current_user(request)
    if not user or not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized"
        )
    return user 