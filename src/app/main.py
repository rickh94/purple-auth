import logging
from pathlib import Path

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from app import config
from app.config import PORTAL_ENABLED, HOST
from app.dependencies import engine
from app.models.client_app_model import ClientApp
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

# TODO: conditionally create portal app and ensure creation in database on startup.
if PORTAL_ENABLED:
    app.include_router(portal_auth_router, prefix="/auth", tags=["portal auth"])

    app.include_router(portal_router, prefix="", tags=["portal"])
    static_path = Path(__file__).parent / "static"
    app.mount(
        "/static", StaticFiles(directory=str(static_path.absolute())), name="static"
    )

    @app.on_event("startup")
    async def ensure_portal_app():
        await user_crud.check_or_create_user_from_email("rickhenry@rickhenry.dev")
        portal_app = await engine.find_one(ClientApp, ClientApp.app_id == "0")
        if not portal_app:
            redirect_url = f"{HOST}/auth/confirm/magic"
            await clientapp_crud.create_client_app(
                app_name="Purple Auth Portal",
                owner="rickhenry@rickhenry.dev",
                redirect_url=redirect_url,
                refresh=True,
                app_id="0",
            )
