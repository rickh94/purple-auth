from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.responses import RedirectResponse

from app import config
from app.dependencies import check_client_app
from app.io.models import AuthRequest, ClientApp
from app.io import email as io_email
from app.security import magic as security_magic, token as security_token

magic_router = APIRouter()


@magic_router.post("/request/{app_id}")
async def request_magic(
    auth_request: AuthRequest, client_app: ClientApp = Depends(check_client_app)
):
    """Request a magic authentication link"""
    magic_link = security_magic.generate(auth_request.email, client_app.app_id)
    try:
        await io_email.send(
            to=auth_request.email,
            subject="Your Magic Sign In Link",
            text=f"Click or copy this link to sign in: {magic_link}. It will expire "
            f"in {config.MAGIC_LIFETIME} minutes.",
            from_name=client_app.name,
        )
    except io_email.EmailError:
        raise HTTPException(status_code=500, detail="Could not send email")
    return "Check your email for a login link."


@magic_router.get("/confirm/{app_id}")
async def confirm_magic(
    secret: str = Query(...),
    id_: str = Query(..., alias="id"),
    client_app: ClientApp = Depends(check_client_app),
):
    if email := security_magic.verify(id_, secret, client_app.app_id):
        id_token = security_token.generate(email, client_app)
        redirect_url = f"{client_app.redirect_url}?idToken={quote_plus(id_token)}"
        if client_app.get_refresh_key():
            refresh_token = await security_token.generate_refresh_token(
                email, client_app
            )
            redirect_url = f"{redirect_url}&refreshToken={quote_plus(refresh_token)}"
        return RedirectResponse(redirect_url)
    if client_app.failure_redirect_url:
        return RedirectResponse(client_app.failure_redirect_url)
    raise HTTPException(status_code=401, detail="Invalid Link.")
