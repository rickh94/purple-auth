from urllib.parse import quote_plus

from fastapi import HTTPException, Depends
from motor import motor_asyncio
from odmantic import AIOEngine

from app import config
from app.io.models import ClientApp

db_uri = "mongodb://{username}:{password}@{host}:{port}".format(
    username=quote_plus(config.DB_USERNAME),
    password=quote_plus(config.DB_PASSWORD),
    host=quote_plus(config.DB_HOST),
    port=quote_plus(config.DB_PORT),
)

db_client = motor_asyncio.AsyncIOMotorClient(db_uri)
engine = AIOEngine(motor_client=db_client, database=config.DB_NAME)


async def check_client_app(app_id: str):
    client_app = await engine.find_one(ClientApp, ClientApp.app_id == app_id)
    if not client_app:
        raise HTTPException(status_code=404, detail="Could not find app.")
    return client_app


async def check_refresh_client_app(client_app: ClientApp = Depends(check_client_app)):
    if not client_app.get_refresh_key():
        raise HTTPException(
            status_code=403, detail="Refreshing isn't supported on this app"
        )
    return client_app
