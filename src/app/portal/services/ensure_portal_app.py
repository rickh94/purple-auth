import mongox

from app import config
from app.models.client_app_model import ClientApp
from app.portal.crud import clientapp_crud


async def ensure_portal_app():
    try:
        portal_app = await ClientApp.query(ClientApp.app_id == "0").get()
    except mongox.NoMatchFound:
        redirect_url = f"{config.HOST}/auth/confirm/magic"
        failure_redirect_url = f"{config.HOST}/login/magic-failed"
        portal_app = await clientapp_crud.create_client_app(
            app_name="Purple Auth Portal",
            owner=config.WEBMASTER_EMAIL,
            redirect_url=redirect_url,
            failure_redirect_url=failure_redirect_url,
            refresh=True,
            app_id="0",
            refresh_token_expire_hours=24 * 5,
            low_quota_threshold=10,
        )
    portal_app.unlimited = True
    await portal_app.save()

    return portal_app
