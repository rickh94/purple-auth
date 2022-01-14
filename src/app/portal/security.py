import logging
from typing import Optional

import purple_auth_client as pac
from fastapi import HTTPException, Security, Depends
from fastapi.openapi.models import OAuthFlows
from fastapi.security import OAuth2
from starlette.requests import Request

from app.config import HOST
from app.portal.crud import user_crud
from app.portal.models.user_model import User

# USE_WHITELIST = bool(os.getenv("USE_WHITELIST"))
# WHITELIST_DOMAINS = os.getenv("WHITELIST_DOMAINS", "").lower().split(",")
# WHITELIST = os.getenv("WHITELIST", "").lower().split(",")
auth_client = pac.AuthClient(HOST, "0")


class ServiceAuthentication(OAuth2):
    def __init__(
        self,
        *args,
        tokenUrl: str,
        authorizationUrl: str,
        token_name: str = None,
        refresh_token_name: str = None,
        **kwargs,
    ):
        flows = OAuthFlows(
            authorizationCode={
                "tokenUrl": tokenUrl,
                "authorizationUrl": authorizationUrl,
            }
        )
        super().__init__(flows=flows, *args, **kwargs)
        self.token_name = token_name or "token"
        self.refresh_token_name = refresh_token_name or "refresh_token"

    def __call__(self, request: Request) -> str:
        """Extract token from cookies"""
        token = request.cookies.get(self.token_name)
        if not token:
            raise HTTPException(status_code=401, detail="Not Authorized")
        return token

    def get_refresh_token(self, request: Request) -> str:
        return request.cookies.get(self.refresh_token_name)


# def validate_email(email) -> bool:
#     if not USE_WHITELIST:
#         return True
#     domain = email.split("@")[-1]
#     if domain.lower() in WHITELIST_DOMAINS or email in WHITELIST:
#         return True
#     return False


oauth2_scheme = ServiceAuthentication(
    tokenUrl="/login/confirm",
    authorizationUrl="/portal/auth/request",
    token_name="id_token",
    refresh_token_name="refresh_token",
)


async def try_refresh(request: Request) -> Optional[str]:
    if refresh_token := oauth2_scheme.get_refresh_token(request):
        new_token = await auth_client.refresh(refresh_token)
        logging.debug(f"Refreshed token: {new_token}")
        return new_token
    logging.debug("No refresh token")
    return None


async def get_current_user(token: str = Security(oauth2_scheme)) -> User:
    credential_exception = HTTPException(status_code=401, detail="Invalid Token")
    try:
        token_result = await auth_client.verify(token)
    except pac.AuthenticationFailure as e:
        if str(e) == "expired":
            raise HTTPException(status_code=401, detail="Expired Token")
        raise credential_exception
    email = token_result["claims"].get("sub")
    if not email:
        raise credential_exception
    user = await user_crud.get_user_by_email(email)
    if not user:
        user = await user_crud.create_user_from_email(email)
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="User is disabled")
    return current_user
