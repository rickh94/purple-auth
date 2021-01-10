from fastapi import APIRouter, Query, Depends, HTTPException

from app.dependencies import check_client_app
from app.io.models import (
    ClientApp,
    VerifiedTokenResponse,
    IssueToken,
    VerifyToken,
    RequestRefresh,
)
from app.security import token as security_token

token_router = APIRouter()


@token_router.get("/verify/{app_id}", response_model=VerifiedTokenResponse)
async def verify_token(
    vt: VerifyToken,
    client_app: ClientApp = Depends(check_client_app),
):
    try:
        headers, claims = security_token.verify(vt.idToken, client_app)
    except security_token.TokenVerificationError:
        raise HTTPException(status_code=401, detail=f"Invalid Token")
    return VerifiedTokenResponse(headers=headers, claims=claims)


@token_router.get("/refresh/{app_id}", response_model=IssueToken)
async def refresh(
    req_res: RequestRefresh,
    client_app: ClientApp = Depends(check_client_app),
):
    if not client_app.get_refresh_key():
        raise HTTPException(
            status_code=403, detail="Refreshing isn't allowed for this app"
        )
    try:
        id_token = await security_token.verify_refresh_token(
            req_res.refreshToken, client_app
        )
    except security_token.TokenVerificationError:
        raise HTTPException(status_code=401, detail="Could not verify refresh token")
    return IssueToken(idToken=id_token, refreshToken=req_res.refreshToken)
