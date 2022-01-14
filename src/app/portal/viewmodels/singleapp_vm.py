from typing import Optional

from fastapi import HTTPException
from starlette.requests import Request

from app.models.client_app_model import ClientApp
from app.portal.crud import clientapp_crud
from app.portal.viewmodels.base_vm import VMBase


class SingleAppVM(VMBase):
    def __init__(self, request: Request, app: Optional[ClientApp] = None):
        super().__init__(request)
        self.app = app

    async def get_app(self, app_id: str):
        if self.app:
            return self.app
        if await self.check_for_user():
            self.app = await clientapp_crud.get_client_app(app_id, self.user)
        else:
            raise HTTPException(status_code=401, detail="Unauthorized")
        return self.app
