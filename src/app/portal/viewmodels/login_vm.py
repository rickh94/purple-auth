from starlette.requests import Request

from app.portal.viewmodels.base_vm import VMBase


class LoginVM(VMBase):
    def __init__(self, request: Request, user_email=None):
        super().__init__(request)
        self.user_email = user_email
