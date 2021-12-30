import logging
from pathlib import Path

import mongox
from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from app import config
from app.config import PORTAL_ENABLED, HOST
from app.models.client_app_model import ClientApp
from app.models.token_models import RefreshToken
from app.portal.routes.auth import portal_auth_router
from app.portal.routes.views import portal_router
from app.routes.client_app import client_app_router
from app.routes.magic import magic_router
from app.routes.otp import otp_router
from app.routes.token import token_router
from app.portal.crud import clientapp_crud, user_crud

app = FastAPI(title="Auth Service", version=config.VERSION)

app.include_router(magic_router, prefix="/magic", tags=["magic"])
app.include_router(otp_router, prefix="/otp", tags=["otp"])
app.include_router(token_router, prefix="/token", tags=["token"])
app.include_router(client_app_router, prefix="/app", tags=["app"])


logging.basicConfig(
    format="[%(asctime)s] %(levelname)s: %(message)s", level=logging.DEBUG
)


@app.on_event("startup")
async def prepare_db():
    await ClientApp.create_indexes()
    await RefreshToken.create_indexes()


# TODO: conditionally create portal app and ensure creation in database on startup.
if PORTAL_ENABLED:
    app.include_router(portal_auth_router, prefix="/auth", tags=["portal auth"])

    app.include_router(portal_router, prefix="", tags=["portal"])
    static_path = Path(__file__).parent / "static"
    app.mount(
        "/static", StaticFiles(directory=str(static_path.absolute())), name="static"
    )

    from app.portal.models.user_model import User

    @app.on_event("startup")
    async def ensure_portal_app():
        await User.create_indexes()
        await user_crud.check_or_create_user_from_email("rickhenry@rickhenry.dev")
        try:
            await ClientApp.query(ClientApp.app_id == "0").get()
        except mongox.NoMatchFound:
            redirect_url = f"{HOST}/auth/confirm/magic"
            await clientapp_crud.create_client_app(
                app_name="Purple Auth Portal",
                owner="rickhenry@rickhenry.dev",
                redirect_url=redirect_url,
                refresh=True,
                app_id="0",
            )
