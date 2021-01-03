from fastapi import APIRouter, Query, Depends, HTTPException

from app.dependencies import check_client_app
from app.io.models import ClientApp, VerifiedTokenResponse
from app.security import token as security_token

token_router = APIRouter()


@token_router.get("/verify/{app_id}", response_model=VerifiedTokenResponse)
async def verify_token(
    id_token: str = Query(..., title="ID Token (JWT)", alias="idToken"),
    client_app: ClientApp = Depends(check_client_app),
):
    try:
        headers, claims = security_token.verify(client_app, id_token)
    except security_token.TokenVerificationError:
        raise HTTPException(status_code=401, detail=f"Invalid Token")
    return VerifiedTokenResponse(headers=headers, claims=claims)
