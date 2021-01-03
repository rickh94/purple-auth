from typing import Optional

from fastapi import APIRouter, Query, HTTPException

from app import config
from app.security import otp as security_otp
from app.io import email as io_email

otp_router = APIRouter()


@otp_router.post("/request")
async def request_otp(email: str = Query(..., title="Email")):
    """Request an authentication code for an email"""
    user_code = security_otp.generate(email)
    try:
        await io_email.send(
            email,
            "Your One Time Login Code",
            f"Your code is {user_code}. It will expire "
            f"in {config.OTP_LIFETIME} minutes.",
        )
    except io_email.EmailError:
        raise HTTPException(status_code=500, detail="Could not send email")


@otp_router.post("/confirm")
async def confirm_otp(
    email: str = Query(..., title="Email"),
    code: str = Query(..., title="One Time Password"),
):
    """Confirm authentication by one time code"""
    if not security_otp.verify(email, code):
        raise HTTPException(status_code=401, detail="Invalid Code.")
