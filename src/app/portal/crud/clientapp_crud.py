import uuid
from typing import Optional, List

import jwcrypto.jwk as jwk
import mongox
from fastapi import HTTPException
from mongox import Q

from app.models.client_app_model import ClientApp
from app.models.token_models import RefreshToken
from app.portal.models.user_model import User
from app.portal.services import deletion_protection


async def create_client_app(
    app_name: str,
    owner: str,
    redirect_url: str,
    failure_redirect_url: str,
    refresh: bool = False,
    app_id: Optional[str] = None,
    refresh_token_expire_hours: int = 24,
    low_quota_threshold: int = 10,
) -> ClientApp:
    key = jwk.JWK.generate(kty="EC", size=2048)
    app_id = app_id or str(uuid.uuid4())
    app = ClientApp(
        name=app_name,
        app_id=app_id,
        owner=owner,
        key=None,
        refresh_key=None,
        refresh_token_expire_hours=None,
        redirect_url=redirect_url,
        low_quota_threshold=low_quota_threshold,
        failure_redirect_url=failure_redirect_url,
    )
    if refresh:
        app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
        app.refresh_token_expire_hours = refresh_token_expire_hours

    app.set_key(key)
    await app.insert()

    return app


async def get_user_apps(user: User) -> List[ClientApp]:
    return (
        await ClientApp.query(ClientApp.owner == user.email)
        .sort(Q.desc(ClientApp.created))
        .all()
    )


async def get_client_app(app_id: str, owner: User) -> ClientApp:
    try:
        return (
            await ClientApp.query(ClientApp.app_id == app_id)
            .query(ClientApp.owner == owner.email)
            .get()
        )
    except mongox.NoMatchFound:
        raise HTTPException(status_code=404, detail="Could not find matching app")
    except mongox.MultipleMatchesFound:
        raise HTTPException(status_code=500, detail="Multiple apps found")


async def update_client_app(
    app_id,
    user,
    app_name,
    redirect_url,
    refresh_enabled,
    refresh_token_expire_hours,
    failure_redirect_url,
    low_quota_threshold,
) -> ClientApp:
    app = await get_client_app(app_id, user)

    app.name = app_name
    app.redirect_url = redirect_url
    app.failure_redirect_url = failure_redirect_url
    app.change_refresh(refresh_enabled)
    app.refresh_token_expire_hours = refresh_token_expire_hours
    app.low_quota_threshold = low_quota_threshold

    await app.save()

    return app


async def delete_user_apps(user: User) -> None:
    """Delete all of a user's apps and all refresh tokens from those apps."""
    user_apps = await ClientApp.query(ClientApp.owner == user.email).all()
    for app in user_apps:
        await RefreshToken.query(RefreshToken.app_id == app.app_id).delete()
        await app.delete()


async def delete_app(app_id: str, user: User) -> str:
    app = await get_client_app(app_id, user)
    if app.deletion_protection:
        raise HTTPException(
            status_code=400,
            detail="You need to turn off deletion protection to delete this app.",
        )
    name = app.name[:]
    await RefreshToken.query(RefreshToken.app_id == app.app_id).delete()
    await app.delete()
    return name


async def rotate_app_keys(app_id: str, user: User) -> ClientApp:
    """
    Replace an app's keys with newly generated ones. This will invalidate all current
    id tokens and refresh tokens. It will also delete all the (now-invalid) refresh
    tokens from the database.

    :param app_id:  The app's id
    :param user: The owner of the app. Other users cannot change an active app's keys.
    :return: updated app
    """
    app = await get_client_app(app_id, user)
    app.set_key(jwk.JWK.generate(kty="EC", size=2048))
    if app.enc_refresh_key:
        app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
    await app.save()
    await RefreshToken.query(RefreshToken.app_id == app.app_id).delete()

    return app


async def disable_deletion_protection(
    app_id: str, user: User, dp_code: str
) -> ClientApp:
    """
    Disable deletion protection for an app

    :param app_id: the app's id
    :param user: the owner of the app
    :param dp_code: one time use code emailed to the owner to authenticate deletion
    :return: the updated app
    """
    app = await get_client_app(app_id, user)
    if not deletion_protection.verify_dp_code(user, app.app_id, dp_code):
        raise HTTPException(400, detail="Invalid deletion protection code.")
    app.deletion_protection = False
    await app.save()
    return app


async def enable_deletion_protection(app_id: str, user: User) -> ClientApp:
    """
    Enable deletion protection for an app.

    :param app_id: the app's id
    :param user: the owner of the app
    :return: the updated app
    """
    app = await get_client_app(app_id, user)
    app.deletion_protection = True
    await app.save()
    return app
