from typing import Optional

from starlette.requests import Request


class VMBase:
    def __init__(self, request: Request):
        self.request: Request = request
        self.error: Optional[str] = None
        self.user_email: Optional[str] = None
        self.is_logged_in: bool = False

    def to_dict(self):
        return self.__dict__
