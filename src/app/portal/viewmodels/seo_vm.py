from starlette.requests import Request

from app import config
from app.portal.viewmodels.base_vm import VMBase


class SeoVM(VMBase):
    def __init__(self, request: Request):
        super().__init__(request)
        self.host = config.HOST
