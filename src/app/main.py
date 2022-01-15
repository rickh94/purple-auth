import logging
from pathlib import Path

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from app import config
from app.config import PORTAL_ENABLED
from app.models.client_app_model import ClientApp
from app.models.token_models import RefreshToken
from app.portal.routes.api import portal_api_router
from app.portal.routes.auth import portal_auth_router
from app.portal.routes.views import portal_router
from app.portal.services.ensure_portal_app import ensure_portal_app
from app.routes.client_app import client_app_router
from app.routes.magic import magic_router
from app.routes.otp import otp_router
from app.routes.token import token_router
from app.portal.crud import user_crud

app = FastAPI(title="Auth Service", version=config.VERSION)

app.include_router(magic_router, prefix="/magic", tags=["magic"])
app.include_router(otp_router, prefix="/otp", tags=["otp"])
app.include_router(token_router, prefix="/token", tags=["token"])
app.include_router(client_app_router, prefix="/app", tags=["app"])

loglevel = logging.DEBUG if config.DEBUG else logging.INFO
logging.basicConfig(format="[%(asctime)s] %(levelname)s: %(message)s", level=loglevel)


@app.on_event("startup")
async def prepare_db():
    await ClientApp.create_indexes()
    await RefreshToken.create_indexes()


if PORTAL_ENABLED:
    app.include_router(portal_auth_router, prefix="/auth", tags=["portal auth"])
    app.include_router(portal_api_router, prefix="/api", tags=["portal api"])

    app.include_router(portal_router, prefix="", tags=["portal"])
    static_path = Path(__file__).parent / "static"
    app.mount(
        "/static", StaticFiles(directory=str(static_path.absolute())), name="static"
    )

    from app.portal.models.user_model import User

    @app.on_event("startup")
    async def prepare_portal_dbs():
        await user_crud.check_or_create_user_from_email(config.WEBMASTER_EMAIL)
        await User.create_indexes()
        await ensure_portal_app()
