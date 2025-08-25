# auth/cognito.py
import requests
from jose import jwt, jwk
from jose.utils import base64url_decode
from fastapi import HTTPException, status

from ..api_config import settings



# Store JWKS keys globally to avoid fetching them on every request
response = requests.get(settings.JWKS_URL)
jwks = response.json()["keys"]


def get_cognito_login_url():
    """Constructs the Cognito Hosted UI login URL."""
    return (
        f"{settings.COGNITO_DOMAIN}/login?response_type=code&client_id={settings.COGNITO_APP_CLIENT_ID}"
        f"&redirect_uri={settings.REDIRECT_URI}&scope=email+openid+profile"
    )

def validate_token(token: str):
    """Validates a JWT token from Cognito."""
    try:
        # 1. Get the key ID (kid) from the token header
        header = jwt.get_unverified_header(token)
        kid = header["kid"]

        # 2. Find the corresponding key in the JWKS
        key = next((k for k in jwks if k["kid"] == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Public key not found in JWKS")

        # 3. Decode and verify the token's signature
        public_key = jwk.construct(key)
        message, encoded_signature = str(token).rsplit(".", 1)
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
        
        if not public_key.verify(message.encode("utf-8"), decoded_signature):
            raise HTTPException(status_code=401, detail="Signature verification failed")
            
        # 4. Verify claims
        claims = jwt.get_unverified_claims(token)
        if claims["iss"] != settings.COGNITO_ISSUER:
            raise HTTPException(status_code=401, detail="Invalid issuer")
        if claims["token_use"] not in ["id", "access"]:
             raise HTTPException(status_code=401, detail="Invalid token use")

        # Note: The `exp` claim (expiration time) is automatically checked by some libraries,
        # but it's good practice to be aware of it.
        
        return claims
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
