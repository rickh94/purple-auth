from fastapi import APIRouter, Depends

from app.dependencies import check_client_app
from app.io.models import ClientApp, ClientAppPublic
from app.security import client_app as security_client_app

client_app_router = APIRouter()


@client_app_router.get("/public_key/{app_id}")
def get_public_key(client_app: ClientApp = Depends(check_client_app)):
    return security_client_app.export_public_key(client_app)


@client_app_router.get("/{app_id}", response_model=ClientAppPublic)
async def get_app_info(client_app: ClientApp = Depends(check_client_app)):
    return ClientAppPublic.parse_obj(client_app)
