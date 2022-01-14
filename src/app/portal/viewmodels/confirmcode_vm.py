from starlette.requests import Request

from app.portal.viewmodels.base_vm import VMBase


class ConfirmCodeVM(VMBase):
    def __init__(self, request: Request, user_email: str, error=None):
        super().__init__(request, error)
        self.user_email = user_email
