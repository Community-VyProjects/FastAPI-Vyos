from fastapi import FastAPI, Request, APIRouter, HTTPException, Query, Depends
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import json
import os
import pathlib
import traceback
from typing import Optional, List, Dict, Any, Callable, Awaitable
import urllib.parse
from dotenv import load_dotenv
import asyncio
import uvicorn
import datetime
from functools import lru_cache
from starlette.middleware.sessions import SessionMiddleware

# Import the VyOS API wrapper
from client import VyOSClient
from utils import VyOSAPIError, merge_cidr_parts
from cache import cache, cached, invalidate_cache
from auth import (
    OIDC_ENABLED, get_current_user, get_login_url, exchange_code_for_token,
    create_session_cookie, get_logout_url, require_auth, require_admin, User
)

# Application state
UNSAVED_CHANGES = False

# Load environment variables from .env file
load_dotenv()

# Directory configuration
BASE_DIR = pathlib.Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# Environment settings
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
IS_PRODUCTION = ENVIRONMENT.lower() == "production"

# API and security settings
API_KEY = os.getenv("VYOS_API_KEY", "Kode30050264")
VYOS_HOST = os.getenv("VYOS_HOST", "")
VYOS_API_URL = os.getenv("VYOS_API_URL", "")
CERT_PATH = os.getenv("CERT_PATH", "")
TRUST_SELF_SIGNED = os.getenv("TRUST_SELF_SIGNED", "false").lower() == "true"
HTTPS = os.getenv("VYOS_HTTPS", "true").lower() == "true"

# Authentication settings
SESSION_SECRET = os.getenv("SESSION_SECRET", "supersecretkey")
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() == "true"

# Debug: Print the actual environment variables being used
print(f"DEBUG: Using VYOS_HOST={VYOS_HOST}")
print(f"DEBUG: Using API_KEY={API_KEY}")

# Extract host from VYOS_API_URL if VYOS_HOST is not set
if not VYOS_HOST and VYOS_API_URL:
    try:
        parsed_url = urllib.parse.urlparse(VYOS_API_URL)
        VYOS_HOST = parsed_url.netloc
        print(f"DEBUG: Extracted VYOS_HOST from API URL: {VYOS_HOST}")
    except Exception:
        pass

# VyOS client initialization
vyos_client = None
if VYOS_HOST and API_KEY:
    try:
        print(f"DEBUG: Initializing VyOSClient with host={VYOS_HOST} and API_KEY={API_KEY}")
        vyos_client = VyOSClient(
            host=VYOS_HOST,
            api_key=API_KEY,
            https=HTTPS,
            cert_path=CERT_PATH,
            trust_self_signed=TRUST_SELF_SIGNED
        )
        
        # Test connection in background after startup
        async def test_connection():
            try:
                print(f"DEBUG: Testing connection with API_KEY={API_KEY}")
                success, error_msg = await vyos_client.test_connection()
                if not success:
                    print(f"❌ CRITICAL: Connection test failed - {error_msg}")
            except Exception as e:
                print(f"❌ CRITICAL: Connection test to VyOS router failed: {e}")
                
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to initialize VyOS client: {e}")
else:
    missing = []
    if not VYOS_HOST:
        missing.append("VYOS_HOST")
    if not API_KEY:
        missing.append("VYOS_API_KEY")
    print(f"CRITICAL ERROR: Cannot initialize VyOS client - missing required configuration: {', '.join(missing)}")

# Create FastAPI app
app = FastAPI(
    title="VyManager",
    description="API for managing VyOS router configurations",
    version="1.0.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-CSRF-Token"],
    expose_headers=["Content-Length", "Content-Type"],
    max_age=86400,
)

# Create API router
api_router = APIRouter(prefix="/api")

# Create Auth router
auth_router = APIRouter(prefix="/auth")

# Add Session Middleware for OIDC state management
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=3600,  # 1 hour
)

# Authentication middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Skip authentication for public routes
    path = request.url.path
    
    public_paths = [
        "/static", 
        "/auth/login", 
        "/auth/callback", 
        "/auth/logout",
        "/"  # Homepage is public
    ]
    
    # Check if the route should be public
    is_public = any(path.startswith(prefix) for prefix in public_paths)
    
    # Skip authentication checks if path is public or auth is disabled
    if not AUTH_ENABLED or is_public or path.startswith("/docs") or path.startswith("/redoc"):
        return await call_next(request)
    
    # For API routes, check for authentication
    if path.startswith("/api"):
        # Check if user is authenticated
        user = await get_current_user(request)
        if not user:
            # For API requests, return 401 Unauthorized
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"}
            )
    
    # For all other routes, check if user is authenticated
    user = await get_current_user(request)
    if not user:
        # For web routes, redirect to login
        login_url = "/"
        return RedirectResponse(url=login_url)
    
    # Attach user to request state for use in route handlers
    request.state.user = user
    
    # Continue processing
    return await call_next(request)

# Security middleware for production
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    if IS_PRODUCTION:
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data:;"
    
    return response

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Dependency for VyOS client
def get_vyos_client():
    if not vyos_client:
        raise HTTPException(
            status_code=503,
            detail="VyOS client not initialized. Check your environment variables."
        )
    return vyos_client

# Helper for handling VyOS API requests
async def handle_vyos_request(request_func: Callable[..., Awaitable[Any]], *args, **kwargs) -> Dict[str, Any]:
    """Generic handler for VyOS API requests with error handling"""
    try:
        result = await request_func(*args, **kwargs)
        return result
    except VyOSAPIError as e:
        return {
            "success": False,
            "error": f"VyOS API Error: {e.message}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc() if not IS_PRODUCTION else None
        }

# Cache key generator for dynamic API handler
def get_cache_key(endpoint_type: str, path_parts: Optional[List[str]] = None) -> str:
    """Generate a cache key for the dynamic API handler"""
    if path_parts:
        return f"dynamic:{endpoint_type}:{':'.join([str(p) for p in path_parts])}"
    return f"dynamic:{endpoint_type}"

# Dynamic API endpoint handler
async def dynamic_vyos_api_handler(endpoint_type: str, path_parts: Optional[List[str]] = None) -> JSONResponse:
    """Dynamically route API requests to the appropriate VyOS API method"""
    if not vyos_client:
        return JSONResponse(
            status_code=503,
            content={
                "success": False,
                "error": "VyOS client not initialized. Check your environment variables."
            }
        )
    
    # Determine if this is a read-only operation that can be cached
    read_only = endpoint_type in ["showConfig", "show"]
    
    # Try to get from cache for read-only operations
    if read_only:
        cache_key = get_cache_key(endpoint_type, path_parts)
        cached_result = cache.get(cache_key)
        if cached_result:
            return JSONResponse(content=cached_result)
    
    try:
        # Get the appropriate client method based on endpoint_type
        method_map = {
            "showConfig": vyos_client.showConfig,
            "show": vyos_client.show,
            "configure_set": vyos_client.configure.set,
            "configure_delete": vyos_client.configure.delete,
            "configure_comment": vyos_client.configure.comment,
            "generate": vyos_client.generate,
            "reset": vyos_client.reset,
            "image": vyos_client.image,
            "config_file": vyos_client.config_file,
            "reboot": vyos_client.reboot,
            "poweroff": vyos_client.poweroff
        }
        
        method = method_map.get(endpoint_type)
        if not method:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": f"Unknown endpoint type: {endpoint_type}"}
            )
        
        # Execute the method with the path parts
        if path_parts:
            if endpoint_type.startswith("configure_"):
                result = await method(path_parts)
            else:
                try:
                    curr_method = method
                    for part in path_parts:
                        if hasattr(curr_method, part):
                            curr_method = getattr(curr_method, part)
                        else:
                            break
                    result = await curr_method()
                except Exception:
                    result = await method(path_parts)
        else:
            result = await method()
        
        # Ensure result is JSON-serializable
        if not isinstance(result, dict):
            try:
                if isinstance(result, str):
                    if result.strip().startswith('{') or result.strip().startswith('['):
                        try:
                            parsed_result = json.loads(result)
                            
                            # Cache read-only results
                            if read_only:
                                cache.set(cache_key, parsed_result, ttl=300)
                                
                            return JSONResponse(content=parsed_result)
                        except json.JSONDecodeError:
                            return JSONResponse(
                                status_code=500,
                                content={
                                    "success": False,
                                    "error": "Invalid JSON response from VyOS",
                                    "raw_data": result[:1000]
                                }
                            )
                    else:
                        response_data = {"success": True, "data": result, "error": None}
                        
                        # Cache read-only results
                        if read_only:
                            cache.set(cache_key, response_data, ttl=300)
                            
                        return JSONResponse(content=response_data)
                else:
                    response_data = {"success": True, "data": str(result), "error": None}
                    
                    # Cache read-only results
                    if read_only:
                        cache.set(cache_key, response_data, ttl=300)
                        
                    return JSONResponse(content=response_data)
            except Exception as e:
                return JSONResponse(
                    status_code=500,
                    content={
                        "success": False,
                        "error": f"Failed to process VyOS response: {str(e)}",
                        "raw_data": str(result)[:1000] if result else None
                    }
                )
        
        # Cache read-only results
        if read_only:
            try:
                json.dumps(result)  # Verify serialization
                cache.set(cache_key, result, ttl=300)
            except (TypeError, ValueError):
                pass  # Skip caching if not serializable
        
        # Verify JSON serialization
        try:
            json.dumps(result)
            return JSONResponse(content=result)
        except (TypeError, ValueError, OverflowError) as e:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": f"Response contains non-serializable data: {str(e)}",
                    "raw_data": str(result)[:1000] if result else None
                }
            )
        
    except VyOSAPIError as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"VyOS API Error: {e.message}"}
        )
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response)

# API Routes for unsaved changes state management
@api_router.get("/check-unsaved-changes")
async def api_check_unsaved():
    """Returns whether there are unsaved changes"""
    return JSONResponse(content={
        "success": True,
        "data": UNSAVED_CHANGES,
        "error": None
    })

@api_router.post("/set-unsaved-changes/{value}")
async def api_set_unsaved_changes(value: bool):
    """Set whether there are unsaved changes"""
    global UNSAVED_CHANGES
    UNSAVED_CHANGES = value
    return JSONResponse(content={"success": True, "error": None})

# API Routes for 'show' operations
@api_router.get("/show/{path:path}")
@cached(ttl=300, key_prefix="show")
async def api_show(path: str):
    """Handle 'show' operation API calls with dynamic paths"""
    path_parts = path.split("/")
    path_parts = merge_cidr_parts(path_parts)
    return await dynamic_vyos_api_handler("show", path_parts)

# API Routes for 'showConfig' operations
@api_router.get("/config/{path:path}")
@cached(ttl=300, key_prefix="config")
async def api_config(path: str = "", client: VyOSClient = Depends(get_vyos_client)):
    """Handle configuration retrieval API calls with dynamic paths"""
    try:
        if not path:
            method = client.showConfig
        else:
            path_parts = path.split("/")
            path_parts = merge_cidr_parts(path_parts)
            path_parts = [part for part in path_parts if part]
            
            method = client.showConfig
            for part in path_parts:
                try:
                    method = getattr(method, part)
                except AttributeError:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "success": False,
                            "error": f"Invalid path segment: '{part}'",
                            "valid_path": path.split(part)[0]
                        }
                    )
        
        result = await method()
        
        # Verify JSON serialization
        try:
            json.dumps(result)
            return JSONResponse(content=result)
        except (TypeError, ValueError, OverflowError) as e:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": f"Response contains non-serializable data: {str(e)}",
                    "raw_data": str(result)[:1000] if result else None
                }
            )
        
    except VyOSAPIError as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"VyOS API Error: {e.message}", "data": None}
        )
    except Exception as e:
        error_response = {
            "success": False,
            "error": f"Error communicating with VyOS router: {str(e)}",
            "data": None
        }
        
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
            
        return JSONResponse(status_code=500, content=error_response)

# Configure operations
@api_router.post("/configure/set/{path:path}")
async def api_configure_set(path: str, value: Optional[str] = None):
    """Handle 'set' configuration operations"""
    if '%2F' in path:
        path = urllib.parse.unquote(path)
        
    path_parts = path.split("/")
    path_parts = merge_cidr_parts(path_parts)
    path_parts = [part for part in path_parts if part]
    
    if value:
        path_parts.append(value)
    
    global UNSAVED_CHANGES
    UNSAVED_CHANGES = True
    
    # Invalidate relevant caches when modifying configuration
    invalidate_cache(pattern="config")
    invalidate_cache(pattern="show")
    
    return await dynamic_vyos_api_handler("configure_set", path_parts)

@api_router.post("/configure/delete/{path:path}")
async def api_configure_delete(path: str, value: Optional[str] = None):
    """Handle 'delete' configuration operations"""
    if '%2F' in path:
        path = urllib.parse.unquote(path)
    
    path_parts = path.split("/")
    path_parts = merge_cidr_parts(path_parts)
    path_parts = [part for part in path_parts if part]
    
    if value:
        path_parts.append(value)

    global UNSAVED_CHANGES
    UNSAVED_CHANGES = True
    
    # Invalidate relevant caches when modifying configuration
    invalidate_cache(pattern="config")
    invalidate_cache(pattern="show")
    
    return await dynamic_vyos_api_handler("configure_delete", path_parts)

@api_router.post("/configure/comment/{path:path}")
async def api_configure_comment(path: str, value: Optional[str] = None):
    """Handle 'comment' configuration operations"""
    if '%2F' in path:
        path = urllib.parse.unquote(path)
    
    path_parts = path.split("/")
    path_parts = merge_cidr_parts(path_parts)
    path_parts = [part for part in path_parts if part]
    
    if value:
        path_parts.append(value)
        
    global UNSAVED_CHANGES
    UNSAVED_CHANGES = True
    
    # Invalidate relevant caches when modifying configuration
    invalidate_cache(pattern="config")
    
    return await dynamic_vyos_api_handler("configure_comment", path_parts)

@api_router.post("/configure/batch")
async def api_configure_batch(operations: List[Dict[str, Any]], client: VyOSClient = Depends(get_vyos_client)):
    """Handle batch configuration operations"""
    global UNSAVED_CHANGES
    UNSAVED_CHANGES = True
    
    # Invalidate relevant caches when modifying configuration
    invalidate_cache(pattern="config")
    invalidate_cache(pattern="show")
    
    try:
        batch = client.configure.batch()
        
        for operation in operations:
            op = operation.get("op")
            path = operation.get("path")
            
            if not op or not path:
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "error": "Each operation must have 'op' and 'path' fields"}
                )
            
            if op == "set":
                batch.set(path)
            elif op == "delete":
                batch.delete(path)
            elif op == "comment":
                batch.comment(path)
            else:
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "error": f"Unknown operation: {op}"}
                )
        
        result = await batch.execute()
        return JSONResponse(content=result)
        
    except VyOSAPIError as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"VyOS API Error: {e.message}"}
        )
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
            
        return JSONResponse(status_code=500, content=error_response)

# Generic operation routes
@api_router.post("/generate/{path:path}")
async def api_generate(path: str):
    """Handle 'generate' operations"""
    path_parts = path.split("/")
    path_parts = merge_cidr_parts(path_parts)
    return await dynamic_vyos_api_handler("generate", path_parts)

@api_router.post("/reset/{path:path}")
async def api_reset(path: str):
    """Handle 'reset' operations"""
    path_parts = path.split("/")
    path_parts = merge_cidr_parts(path_parts)
    return await dynamic_vyos_api_handler("reset", path_parts)

# Image management operations
@api_router.post("/image/add")
async def api_image_add(url: str, client: VyOSClient = Depends(get_vyos_client)):
    """Handle 'image add' operations"""
    try:
        result = await client.image.add(url)
        return JSONResponse(content=result)
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response)

@api_router.post("/image/delete")
async def api_image_delete(name: str, client: VyOSClient = Depends(get_vyos_client)):
    """Handle 'image delete' operations"""
    try:
        result = await client.image.delete(name)
        return JSONResponse(content=result)
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response)

# Config file operations
@api_router.post("/config-file/save")
async def api_config_file_save(file: Optional[str] = None, client: VyOSClient = Depends(get_vyos_client)):
    """Handle 'config-file save' operations"""
    try:
        result = await client.config_file.save(file)
        
        # Invalidate configuration cache after saving
        invalidate_cache(pattern="config")
        
        return JSONResponse(content=result)
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response)

@api_router.post("/config-file/load")
async def api_config_file_load(file: str, client: VyOSClient = Depends(get_vyos_client)):
    """Handle 'config-file load' operations"""
    try:
        result = await client.config_file.load(file)
        
        # Invalidate all caches after loading configuration
        invalidate_cache()
        
        return JSONResponse(content=result)
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response)

# System operations
@api_router.post("/reboot")
async def api_reboot(client: VyOSClient = Depends(get_vyos_client)):
    """Handle 'reboot' operations"""
    try:
        result = await client.reboot()
        return JSONResponse(content=result)
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response)

@api_router.post("/poweroff")
async def api_poweroff(client: VyOSClient = Depends(get_vyos_client)):
    """Handle 'poweroff' operations"""
    try:
        result = await client.poweroff()
        return JSONResponse(content=result)
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response)

# DHCP leases parsing
@lru_cache(maxsize=16)
def parse_dhcp_leases(leases_string: str) -> Dict[str, List[Dict[str, str]]]:
    """Parse the DHCP leases string into a structured format"""
    lines = leases_string.strip().split('\n')
    
    if len(lines) < 2:
        return {}
    
    leases = []
    subnet_leases = {}
    
    for i in range(1, len(lines)):
        line = lines[i].strip()
        
        if not line or '---' in line:
            continue
        
        parts = line.split()
        
        if len(parts) < 5:
            continue
        
        try:
            ip_address = parts[0] if len(parts) > 0 else "Unknown"
            mac_address = parts[1] if len(parts) > 1 else "Unknown"
            state = parts[2] if len(parts) > 2 else "Unknown"
            
            lease_start = "Unknown"
            lease_end = "Unknown"
            remaining = "Unknown"
            pool = "Unknown"
            hostname = "Unknown"
            origin = "Unknown"
            
            if len(parts) > 3:
                lease_start = f"{parts[3]} {parts[4]}" if len(parts) > 4 else parts[3]
                
            if len(parts) > 5:
                lease_end = f"{parts[5]} {parts[6]}" if len(parts) > 6 else parts[5]
            
            if len(parts) > 7:
                remaining = parts[7]
            
            if len(parts) > 8:
                pool = parts[8]
            
            if len(parts) > 9:
                hostname = parts[9]
            
            if len(parts) > 10:
                origin = parts[10]
            
            lease = {
                "ip_address": ip_address,
                "mac_address": mac_address,
                "state": state,
                "lease_start": lease_start,
                "lease_end": lease_end,
                "remaining": remaining,
                "pool": pool,
                "hostname": hostname,
                "origin": origin
            }
            
            leases.append(lease)
            
            if pool not in subnet_leases:
                subnet_leases[pool] = []
            subnet_leases[pool].append(lease)
            
        except Exception:
            continue
    
    return subnet_leases if subnet_leases else {"LAN": []}

# DHCP leases API
@api_router.get("/dhcp/leases")
@cached(ttl=300, key_prefix="dhcp_leases")
async def api_dhcp_leases(client: VyOSClient = Depends(get_vyos_client)):
    """Get DHCP server leases information"""
    try:
        result = await client.show.dhcp.server.leases()
        
        if result.get("success", False) and result.get("data"):
            leases_data = parse_dhcp_leases(result["data"])
            return JSONResponse(content={
                "success": True,
                "leases": leases_data,
                "error": None
            })
        
        return JSONResponse(
            status_code=500,
            content={
                "success": result.get("success", False),
                "leases": {},
                "error": result.get("error", "Unknown error")
            }
        )
            
    except VyOSAPIError as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"VyOS API Error: {e.message}"}
        )
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response)

# Routing table API
@api_router.get("/routingtable")
@cached(ttl=300, key_prefix="routing_table")
async def api_routing_table(client: VyOSClient = Depends(get_vyos_client)):
    """Get routing table information from the VyOS router"""
    try:
        result = await client.show.ip.route.vrf.all.json()
        
        if result.get("success", False) and result.get("data"):
            try:
                import json

                # Handle FRR 1.4 multiple VRF JSON format
                parts = result['data'].split('}\n{')
                if len(parts) > 1:
                    parts = [parts[0] + '}'] + ['{' + part + '}' for part in parts[1:-1]] + ['{' + parts[-1]]
                    routes_data = {}
                    for obj in parts:
                        data = json.loads(obj)
                        for prefix, routes in data.items():
                            for route in routes:
                                vrf = route.get("vrfName", "default")
                                routes_data.setdefault(vrf, {}).setdefault(prefix, []).append(route)  
                else:
                    routes_data = json.loads(result["data"].split('}{}')[0])

                routes_by_vrf = {}
                total_routes = 0

                # Check if using FRR 1.5 format
                if routes_data.get("default"):
                    vrf_list = list(routes_data.keys())
                    route_new_format = True
                else:
                    vrf_list = ['default']
                    route_new_format = False

                for vrf in vrf_list:
                    if route_new_format:
                        route_path = routes_data.get(vrf)
                    else:
                        route_path = routes_data

                    for prefix, routes_list in route_path.items():
                        for route in routes_list:
                            # Skip loopback address routes
                            if '127.0.0.0/8' in prefix:
                                continue

                            vrf_name = route.get("vrfName", "default")
                            
                            if vrf_name not in routes_by_vrf:
                                routes_by_vrf[vrf_name] = []
                            
                            formatted_route = {
                                "destination": prefix,
                                "prefix_length": route.get("prefixLen"),
                                "protocol": route.get("protocol"),
                                "vrf": vrf_name,
                                "selected": route.get("selected", False),
                                "installed": route.get("installed", False),
                                "distance": route.get("distance"),
                                "metric": route.get("metric"),
                                "uptime": route.get("uptime", ""),
                                "nexthops": []
                            }
                            
                            nexthops = route.get("nexthops", [])
                            for nexthop in nexthops:
                                nh_info = {
                                    "ip": nexthop.get("ip", "directly connected"),
                                    "interface": nexthop.get("interfaceName", ""),
                                    "active": nexthop.get("active", False),
                                    "directly_connected": nexthop.get("directlyConnected", False)
                                }
                                formatted_route["nexthops"].append(nh_info)
                            
                            routes_by_vrf[vrf_name].append(formatted_route)
                            total_routes += 1

                response_data = {
                    "success": True,
                    "routes_by_vrf": routes_by_vrf,
                    "error": None,
                    "count": total_routes,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                
                return JSONResponse(content=response_data, media_type="application/json")
                
            except json.JSONDecodeError as e:
                return JSONResponse(
                    status_code=500,
                    content={"success": False, "error": f"Failed to parse routing table data: {str(e)}"},
                    media_type="application/json"
                )
        
        return JSONResponse(
            status_code=500,
            content={
                "success": result.get("success", False),
                "routes_by_vrf": {},
                "error": result.get("error", "Unknown error")
            },
            media_type="application/json"
        )
            
    except VyOSAPIError as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"VyOS API Error: {e.message}"},
            media_type="application/json"
        )
    except Exception as e:
        error_response = {"success": False, "error": str(e)}
        if not IS_PRODUCTION:
            error_response["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=500, content=error_response, media_type="application/json")

# GraphQL API
@api_router.post("/graphql")
async def graphql_endpoint(request: Request, client: VyOSClient = Depends(get_vyos_client)):
    """GraphQL endpoint that accepts operation names and variables"""
    try:
        body = await request.json()
        operation_name = body.get("operationName")
        variables = body.get("variables", {})
        
        if not operation_name:
            return {"success": False, "error": "Operation name is required", "data": None}
        
        result = await client.graphql.operation(name=operation_name, data=variables)
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e), "data": None}

# Auth routes for OIDC
@auth_router.get("/login")
async def login(request: Request):
    """Initiate OIDC login flow"""
    if not OIDC_ENABLED:
        return {"detail": "OIDC authentication is not configured"}
    
    try:
        # Get login URL from OIDC provider
        login_url = await get_login_url(request)
        return RedirectResponse(url=login_url)
    except Exception as e:
        if not IS_PRODUCTION:
            return {"error": str(e)}
        return RedirectResponse(url="/")

@auth_router.get("/callback")
async def auth_callback(request: Request, code: str, state: Optional[str] = None):
    """Handle OIDC callback after successful authentication"""
    if not OIDC_ENABLED:
        return RedirectResponse(url="/")
    
    # Validate state to prevent CSRF
    session_state = request.session.get("oidc_state")
    if not session_state or session_state != state:
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid state parameter"}
        )
    
    try:
        # Exchange code for tokens
        tokens = await exchange_code_for_token(code)
        
        # Extract tokens
        id_token = tokens.get("id_token")
        access_token = tokens.get("access_token")
        expires_in = tokens.get("expires_in", 3600)
        
        if not id_token or not access_token:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid token response"}
            )
        
        # Create session cookies
        session_data = await create_session_cookie(id_token, access_token, expires_in)
        
        # Create response
        response = RedirectResponse(url="/")
        
        # Set cookies
        response.set_cookie(
            key="session_token",
            value=session_data["session_token"],
            httponly=True,
            secure=IS_PRODUCTION,
            max_age=expires_in,
            samesite="lax"
        )
        
        # Store id_token for logout
        response.set_cookie(
            key="id_token",
            value=id_token,
            httponly=True,
            secure=IS_PRODUCTION,
            max_age=expires_in,
            samesite="lax"
        )
        
        return response
    except Exception as e:
        if not IS_PRODUCTION:
            return JSONResponse(
                status_code=500,
                content={"detail": str(e)}
            )
        return RedirectResponse(url="/")

@auth_router.get("/logout")
async def logout(request: Request):
    """Logout user and redirect to OIDC provider logout"""
    id_token = request.cookies.get("id_token")
    
    # Get logout URL from OIDC provider
    logout_url = await get_logout_url(id_token)
    
    # Create response
    response = RedirectResponse(url=logout_url)
    
    # Clear cookies
    response.delete_cookie("session_token")
    response.delete_cookie("id_token")
    
    return response

@auth_router.get("/user")
async def get_user(request: Request):
    """Get current user information"""
    user = await get_current_user(request)
    if not user:
        return JSONResponse(
            status_code=401,
            content={"detail": "Not authenticated"}
        )
    
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "roles": user.roles,
        "is_admin": user.is_admin
    }

# Legacy redirect for backwards compatibility
@app.get("/dhcpleases")
async def legacy_dhcpleases_redirect():
    """Legacy endpoint that redirects to the new API endpoint"""
    return RedirectResponse(url="/api/dhcp/leases")

# Cache management routes
@api_router.get("/cache/stats")
async def api_cache_stats():
    """Get cache statistics"""
    return JSONResponse(content={
        "success": True,
        "stats": cache.stats(),
        "error": None
    })

@api_router.post("/cache/clear")
async def api_cache_clear(pattern: Optional[str] = None):
    """Clear the cache"""
    if pattern:
        count = cache.delete_pattern(pattern)
        message = f"Cleared {count} cache entries matching pattern: {pattern}"
    else:
        cache.clear()
        message = "Cache cleared completely"
    
    return JSONResponse(content={
        "success": True,
        "message": message,
        "error": None
    })

# Authentication API routes
@api_router.get("/auth/status")
async def api_auth_status(request: Request):
    """Check authentication status"""
    if not AUTH_ENABLED:
        return JSONResponse(content={
            "success": True,
            "authenticated": True,  # Always authenticated when auth is disabled
            "auth_enabled": False,
            "user": None
        })
    
    user = await get_current_user(request)
    return JSONResponse(content={
        "success": True,
        "authenticated": user is not None,
        "auth_enabled": AUTH_ENABLED,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "roles": user.roles,
            "is_admin": user.is_admin
        } if user else None
    })

@api_router.get("/auth/login-url")
async def api_auth_login_url(request: Request):
    """Get login URL for OIDC"""
    if not AUTH_ENABLED or not OIDC_ENABLED:
        return JSONResponse(content={
            "success": False,
            "error": "Authentication is not enabled"
        })
    
    try:
        login_url = await get_login_url(request)
        return JSONResponse(content={
            "success": True,
            "login_url": login_url
        })
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": str(e)
            }
        )

# Include API router
app.include_router(api_router)

# Include Auth router
app.include_router(auth_router)

# Startup event to run connection test
@app.on_event("startup")
async def startup_event():
    if vyos_client:
        asyncio.create_task(test_connection())

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main application page"""
    user = await get_current_user(request)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "auth_enabled": AUTH_ENABLED
    })

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the dashboard page"""
    # Get cache statistics
    cache_stats = cache.stats()
    
    # Format the statistics for display
    hit_rate_percent = round(cache_stats["hit_rate"] * 100, 2)
    uptime_minutes = round(cache_stats["uptime"] / 60, 2)
    
    cache_data = {
        "items": cache_stats["items"],
        "hits": cache_stats["hits"],
        "misses": cache_stats["misses"],
        "hit_rate": f"{hit_rate_percent}%",
        "uptime": f"{uptime_minutes} minutes"
    }
    
    user = await get_current_user(request)
    
    # Check if user is admin when auth is enabled
    is_admin = user and user.is_admin if AUTH_ENABLED else True
    
    if AUTH_ENABLED and not is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return templates.TemplateResponse(
        "dashboard.html", 
        {
            "request": request, 
            "cache_data": cache_data,
            "app_version": "1.0.0",
            "vyos_host": VYOS_HOST,
            "is_production": IS_PRODUCTION,
            "user": user,
            "auth_enabled": AUTH_ENABLED
        }
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3001, reload=True) 
