from fastapi import APIRouter, Query, Depends, HTTPException, Header

from app.dependencies import (
    check_client_app,
    check_refresh_client_app,
)
from app.io.models import (
    ClientApp,
    VerifiedTokenResponse,
    IssueToken,
    VerifyToken,
    RequestRefresh,
)
from app.security import token as security_token

token_router = APIRouter()


@token_router.post("/verify/{app_id}", response_model=VerifiedTokenResponse)
async def verify_token(
    vt: VerifyToken,
    client_app: ClientApp = Depends(check_client_app),
):
    """Ask the server to verify a token for a specific app"""
    try:
        headers, claims = security_token.verify(vt.idToken, client_app)
    except security_token.TokenVerificationError:
        raise HTTPException(status_code=401, detail=f"Invalid Token")
    return VerifiedTokenResponse(headers=headers, claims=claims)


@token_router.post("/refresh/{app_id}", response_model=IssueToken)
async def refresh(
    req_res: RequestRefresh,
    client_app: ClientApp = Depends(check_refresh_client_app),
):
    """Request a new idToken using a refresh token issued by this server."""
    try:
        id_token = await security_token.verify_refresh_token(
            req_res.refreshToken, client_app
        )
    except security_token.TokenVerificationError:
        raise HTTPException(status_code=401, detail="Could not verify refresh token")
    return IssueToken(idToken=id_token, refreshToken=req_res.refreshToken)


@token_router.delete("/refresh/{app_id}", status_code=204)
async def delete_all_refresh_tokens(
    client_app: ClientApp = Depends(check_refresh_client_app),
    token_info: dict = Depends(security_token.authorization_header),
):
    """Delete all of a user's refresh tokens. (Log out everywhere)"""
    await security_token.delete_all_refresh_tokens(
        token_info["claims"]["sub"], client_app
    )


@token_router.delete("/refresh/{app_id}/{refresh_token}", status_code=204)
async def delete_refresh_token(
    refresh_token: str,
    client_app: ClientApp = Depends(check_refresh_client_app),
    _token_info: dict = Depends(security_token.authorization_header),
):
    """Delete a user's refresh token"""
    try:
        await security_token.delete_refresh_token(refresh_token, client_app)
    except security_token.TokenVerificationError:
        raise HTTPException(status_code=401, detail="Could not verify refresh token")
