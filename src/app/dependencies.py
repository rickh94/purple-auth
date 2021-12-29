import datetime
from urllib.parse import quote_plus

from fastapi import HTTPException, Depends
from motor import motor_asyncio
from odmantic import AIOEngine

from app import config
from app.models.client_app_model import ClientApp
from app.io import email as io_email

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


# TODO: Some of these values should probably be un-hardcoded
async def client_app_use_quota(client_app: ClientApp = Depends(check_client_app)):
    if client_app.quota < 1:
        await io_email.send(
            to=client_app.owner,
            subject=f"{client_app.name} is out of Authentications",
            text=f"{client_app.name} has reached its quota of authentications. No "
            f"further authentications will be processed. Please reply to this "
            f"email to purchase more.\nRick Henry\nRick Henry Development\n"
            f"https://rickhenry.dev",
            from_name="Rick Henry",
            reply_to="rickhenry@rickhenry.dev",
        )
        raise HTTPException(
            status_code=503,
            detail="This app does not have any authentications remaining. "
            "Please contact your administrator",
        )
    client_app.quota -= 1
    if client_app.quota < client_app.low_quota_threshold:
        time_since_last_notification = (
            datetime.datetime.now() - client_app.low_quota_last_notified
        )
        if time_since_last_notification >= datetime.timedelta(days=1):
            await io_email.send(
                to=client_app.owner,
                subject=f"{client_app.name} is almost out of Authentications",
                text=f"{client_app.name} has almost reached its quota of "
                f"authentications. It will process {client_app.quota} more "
                f"authentications before it stops authenticating users. "
                f"Please reply to this email to purchase more.\nRick Henry"
                f"\nRick Henry Development\nhttps://rickhenry.dev",
                from_name="Rick Henry",
                reply_to="rickhenry@rickhenry.dev",
            )

    await engine.save(client_app)
    return client_app


async def check_refresh_client_app(client_app: ClientApp = Depends(check_client_app)):
    if not client_app.get_refresh_key():
        raise HTTPException(
            status_code=403, detail="Refreshing isn't supported on this app"
        )
    return client_app
