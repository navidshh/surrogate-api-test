from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from contextlib import asynccontextmanager
import os
import logging
from typing import Optional, Dict, Any

from jose import jwt, jwk  # still needed if used in auth
from jose.utils import base64url_decode

from .api_config import settings
from .routes import auth, tests, surrogate_model
from .auth.cognito import get_cognito_login_url
from .auth.dependency_functions import get_current_user

BASE_DIR = os.path.dirname(__file__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- App Lifecycle (no Redis now) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context (startup & shutdown).
    Previously handled Redis initialization, now simplified.
    """
    logger.info("Starting application without Redis...")
    yield
    logger.info("Shutting down application...")

# --- FastAPI Initialization ---
app = FastAPI(
    lifespan=lifespan,
    title="Surrogate Model API",
    swagger_ui_init_oauth={
        "clientId": settings.COGNITO_APP_PUBLIC_CLIENT_ID,
        "scopes": {"openid"},
        "usePkceWithAuthorizationCodeGrant": True,
    }
)

# --- Static & Template Setup ---
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "static"))

# --- Routers ---
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(tests.router, prefix="/tests", tags=["Test"])
app.include_router(surrogate_model.router, prefix="/surrogate_model", tags=["Surrogate Model"])

# --- Health Check ---
@app.get("/health")
async def health_check():
    return JSONResponse(status_code=200, content={
        "status": "ok",
        "message": "Server is healthy"
    })

# --- Example API Endpoint ---
@app.get("/api/v1/data", response_class=JSONResponse)
async def get_sample_data(user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    """Returns sample data to authenticated users."""
    sample_data = {
        "message": f"Hello, {user.get('email', 'user')}!",
        "data": {
            "items": [
                {"id": 1, "value": "foo"},
                {"id": 2, "value": "bar"},
                {"id": 3, "value": "baz"},
            ]
        }
    }
    return JSONResponse(content=sample_data)

# --- UI Endpoints ---
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home(request: Request):
    context = {
        "request": request,
        "user": {},
        "cognito_login_url": get_cognito_login_url()
    }
    return templates.TemplateResponse("index.html", context)

@app.get("/entry")
async def root():
    return PlainTextResponse("Welcome to the application (v4.0.1). Try the /app or /health endpoints.")

@app.get("/profile", response_class=HTMLResponse, include_in_schema=False)
async def profile(request: Request, user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    context = {
        "request": request,
        "user": user,
        "cognito_login_url": get_cognito_login_url()
    }
    return templates.TemplateResponse("profile.html", context)

# --- Entry Point ---
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
