from starlette.requests import Request

from app.portal.viewmodels.base_vm import VMBase


class HowItWorksVM(VMBase):
    def __init__(self, request: Request):
        super().__init__(request)
