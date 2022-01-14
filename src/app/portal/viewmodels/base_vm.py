from typing import Optional

from fastapi import HTTPException
from starlette.requests import Request

from app import config
from app.portal.models.user_model import User
from app.portal.security import oauth2_scheme, get_current_user


class VMBase:
    def __init__(
        self,
        request: Request,
        error: Optional[str] = None,
        user: Optional[User] = None,
        message: Optional[str] = None,
    ):
        self.request: Request = request
        self.error: Optional[str] = error
        self.user: Optional[User] = user
        self.message: Optional[str] = message
        self.config = {
            "webmaster_email": config.WEBMASTER_EMAIL,
        }

    def to_dict(self):
        return self.__dict__

    async def check_for_user(self):
        """
        Checks for an authenticated user without throwing an exception and redirecting.
        :return: True if a user is authenticated, False otherwise.
        """
        if self.user:
            return True
        token = self.request.cookies.get(oauth2_scheme.token_name)
        if not token:
            self.user = None
            return False
        try:
            self.user = await get_current_user(token)
            return True
        except (HTTPException, ValueError):
            self.user = None
            return False
