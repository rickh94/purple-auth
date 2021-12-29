from fastapi import APIRouter, HTTPException, Depends

from app import config
from app.dependencies import check_client_app, client_app_use_quota
from app.io import email as io_email
from app.models.client_app_model import ClientApp
from app.models.auth_models import AuthRequest, ConfirmCode
from app.models.token_models import IssueToken
from app.security import otp as security_otp, token as security_token

otp_router = APIRouter()


@otp_router.post("/request/{app_id}")
async def request_otp(
    auth_request: AuthRequest,
    client_app: ClientApp = Depends(client_app_use_quota),
):
    """Request an authentication code for an email"""
    user_code = security_otp.generate(auth_request.email, client_app.app_id)
    try:
        await io_email.send(
            to=auth_request.email,
            subject="Your One Time Login Code",
            text=f"Your code is {user_code}. It will expire "
            f"in {config.OTP_LIFETIME} minutes.",
            from_name=client_app.name,
        )
    except io_email.EmailError:
        raise HTTPException(status_code=500, detail="Could not send email")
    return "Check your email for a login code"


@otp_router.post("/confirm/{app_id}", response_model=IssueToken)
async def confirm_otp(
    confirm_code: ConfirmCode,
    client_app: ClientApp = Depends(check_client_app),
):
    """Confirm authentication by one time code"""
    if not security_otp.verify(
        confirm_code.email, confirm_code.code, client_app.app_id
    ):
        raise HTTPException(status_code=401, detail="Invalid Code.")
    id_token = security_token.generate(confirm_code.email, client_app)
    refresh_token = None
    if client_app.get_refresh_key():
        refresh_token = await security_token.generate_refresh_token(
            confirm_code.email, client_app
        )
    return IssueToken(idToken=id_token, refreshToken=refresh_token)
