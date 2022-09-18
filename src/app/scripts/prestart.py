import asyncio

from app import config
from app.portal.crud import user_crud
from app.portal.models.user_model import User
from app.portal.services.ensure_portal_app import ensure_portal_app


async def setup_portal():
    await user_crud.check_or_create_user_from_email(config.WEBMASTER_EMAIL)
    await User.create_indexes()
    await ensure_portal_app()


if __name__ == "__main__":
    if config.PORTAL_ENABLED:
        asyncio.run(setup_portal())
