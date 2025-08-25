# routes/auth.py
import base64
import requests
import boto3
from fastapi import APIRouter, Form, HTTPException
from ..api_config import settings
from fastapi.responses import HTMLResponse, RedirectResponse
from ..auth.cognito import validate_token

router = APIRouter()

@router.post("/token")
async def login_for_access_token(
    username: str = Form(...),
    password: str = Form(...)
):
    """
    Direct authentication endpoint using username/password
    """
    client = boto3.client('cognito-idp', region_name=settings.COGNITO_REGION)
    try:
        response = client.initiate_auth(
            ClientId=settings.COGNITO_APP_PUBLIC_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )

        return {
            "access_token": response['AuthenticationResult']['AccessToken'],
            "token_type": "Bearer",
            "expires_in": response['AuthenticationResult']['ExpiresIn']
        }
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.get("/callback", include_in_schema=False)
async def auth_callback(code: str):
    """Handles the redirect from Cognito after login."""
    # 1. Exchange authorization code for tokens
    auth_str = f"{settings.COGNITO_APP_CLIENT_ID}:{settings.COGNITO_APP_CLIENT_SECRET}"
    b64_auth_str = base64.b64encode(auth_str.encode()).decode()
    
    token_request_data = {
        "grant_type": "authorization_code",
        "client_id": settings.COGNITO_APP_CLIENT_ID,
        "code": code,
        "redirect_uri": settings.REDIRECT_URI,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {b64_auth_str}"
    }
    
    res = requests.post(settings.TOKEN_URL, data=token_request_data, headers=headers)
    if res.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Failed to get tokens: {res.text}")

    tokens = res.json()
    id_token = tokens.get("id_token")

    # 2. Validate the ID Token
    try:
        validate_token(id_token)
    except HTTPException as e:
         return HTMLResponse(f"<h1>Error</h1><p>Invalid Token: {e.detail}</p>", status_code=401)


    # 3. Create a session and redirect
    response = RedirectResponse(url="/profile")
    response.set_cookie(
        key="session_token",
        value=id_token, # We use the ID token for session state
        httponly=True,  # Makes the cookie inaccessible to JavaScript
        secure=False,   # Set to True in production (HTTPS)
        samesite="lax",
    )
    return response

@router.get("/logout", include_in_schema=False)
async def logout():
    """Logs the user out by clearing the session cookie."""
    response = RedirectResponse(url="/")
    response.delete_cookie("session_token")
    return response