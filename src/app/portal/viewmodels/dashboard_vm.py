from typing import List

from starlette.requests import Request

from app.models.client_app_model import ClientApp
from app.portal.crud import clientapp_crud
from app.portal.viewmodels.base_vm import VMBase


class DashboardVM(VMBase):
    def __init__(self, request: Request):
        super().__init__(request)
        self.apps: List[ClientApp] = []

    async def get_user_apps(self):
        self.apps = await clientapp_crud.get_user_apps(self.user)
        return self.apps
