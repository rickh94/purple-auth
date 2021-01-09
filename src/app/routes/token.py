from fastapi import APIRouter, Query, Depends, HTTPException

from app.dependencies import check_client_app
from app.io.models import ClientApp, VerifiedTokenResponse, IssueToken
from app.security import token as security_token

token_router = APIRouter()


@token_router.get("/verify/{app_id}", response_model=VerifiedTokenResponse)
async def verify_token(
    id_token: str = Query(..., title="ID Token (JWT)", alias="idToken"),
    client_app: ClientApp = Depends(check_client_app),
):
    try:
        headers, claims = security_token.verify(id_token, client_app)
    except security_token.TokenVerificationError:
        raise HTTPException(status_code=401, detail=f"Invalid Token")
    return VerifiedTokenResponse(headers=headers, claims=claims)


@token_router.get("/refresh/{app_id}", response_model=IssueToken)
async def refresh(
    refresh_token: str = Query(..., title="Refresh Token", alias="refreshToken"),
    client_app: ClientApp = Depends(check_client_app),
):
    if not client_app.get_refresh_key():
        raise HTTPException(
            status_code=403, detail="Refreshing isn't allowed for this app"
        )
    try:
        id_token = await security_token.verify_refresh_token(refresh_token, client_app)
    except security_token.TokenVerificationError:
        raise HTTPException(status_code=401, detail="Could not verify refresh token")
    return IssueToken(idToken=id_token, refreshToken=refresh_token)
