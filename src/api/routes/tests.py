# routes/tests.py
import os
import sys
import time
import logging
from io import BytesIO
from typing import Optional, Dict, Any, List

import openpyxl
from fastapi import (
    APIRouter, BackgroundTasks, Response, HTTPException, Header,
    Depends, UploadFile, File, Request
)
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from ..auth.dependency_functions import get_current_token, require_user, TokenInfo, get_current_user
from ..auth.cognito import validate_token

# --------------------------------------------------------------------
# Logging setup
# --------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------
# Router setup
# --------------------------------------------------------------------
router = APIRouter()

# --------------------------------------------------------------------
# Basic test endpoints
# --------------------------------------------------------------------
@router.get("/test")
def test_endpoint():
    """Simple connectivity test endpoint."""
    logger.info("Test endpoint called")
    return {"message": "Test OK with logging"}

# --------------------------------------------------------------------
# Auth-protected routes
# --------------------------------------------------------------------
@router.get("/protected", response_model=dict)
async def protected_route(token_info: TokenInfo = Depends(get_current_token)):
    """
    Protected endpoint that supports both OAuth2 and Bearer token authentication.
    Returns token metadata for validation testing.
    """
    return {
        "message": "You have access!",
        "auth_method": token_info.auth_method,
        "token_type": token_info.token_type,
        "token_preview": (
            f"{token_info.token[:20]}..." if len(token_info.token) > 20 else token_info.token
        )
    }

# --------------------------------------------------------------------
# Excel processing endpoint
# --------------------------------------------------------------------
@router.post("/process-excel/")
async def process_excel(file: UploadFile = File(...)):
    """
    Example endpoint to upload and process an Excel file in-memory.
    """
    contents = await file.read()
    input_stream = BytesIO(contents)

    wb = openpyxl.load_workbook(input_stream)
    ws = wb.active
    ws["A1"] = "Processed by API"

    output_stream = BytesIO()
    wb.save(output_stream)
    output_stream.seek(0)

    return StreamingResponse(
        output_stream,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=processed.xlsx"}
    )

# --------------------------------------------------------------------
# Logout endpoint
# --------------------------------------------------------------------
@router.get("/logUserOut", summary="Logs the user out by clearing the session cookie.")
async def logout(response: Response):
    """
    Logs out the current user by clearing authentication cookies.
    """
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("session_token")
    return {"message": "User logged out locally."}

# --------------------------------------------------------------------
# Cognito group endpoints
# --------------------------------------------------------------------
@router.get("/api/v1/user/groups", response_model=List[str], summary="Get user's Cognito groups")
async def get_user_groups(user: dict = Depends(require_user)):
    """
    Returns the Cognito groups for the current authenticated user.
    """
    return user.get("cognito:groups", [])

@router.get("/api/v1/user/groups2", response_model=List[str], summary="Get user's Cognito groups (token-based)")
async def get_user_groups_token(token_info: TokenInfo = Depends(get_current_token)):
    """
    Returns the Cognito groups using direct token validation.
    """
    try:
        user_claims = validate_token(token_info.token)
    except HTTPException as e:
        raise e

    return user_claims.get("cognito:groups", [])

# --------------------------------------------------------------------
# Simulated background task endpoint (formerly rate-limited)
# --------------------------------------------------------------------
@router.post("/run-task/")
async def run_task(
    background_tasks: BackgroundTasks,
    x_user_id: str = Header(...),
    x_user_role: str = Header("Free-Tier")
):
    """
    Simulates a simple background task.
    (Previously rate-limited and Redis-backed, now simplified.)
    """
    logger.info(f"Starting simulated task for user '{x_user_id}' with role '{x_user_role}'...")
    time.sleep(2)
    logger.info(f"Task for user '{x_user_id}' completed.")
    return {"status": "Task completed successfully", "user": x_user_id, "role": x_user_role}
