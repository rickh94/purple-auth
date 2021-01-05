from fastapi import APIRouter, Query, HTTPException, Depends, Body
from starlette.responses import RedirectResponse

from app import config
from app.dependencies import check_client_app
from app.io import email as io_email
from app.io.models import ClientApp, IssueToken, AuthRequest, ConfirmCode
from app.security import otp as security_otp, token as security_token

otp_router = APIRouter()


@otp_router.post("/request/{app_id}")
async def request_otp(
    auth_request: AuthRequest,
    client_app: ClientApp = Depends(check_client_app),
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
    return IssueToken(idToken=id_token)
