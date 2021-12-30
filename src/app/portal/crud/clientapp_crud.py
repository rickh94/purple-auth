import uuid
from typing import Optional

import jwcrypto.jwk as jwk

from app.models.client_app_model import ClientApp


async def create_client_app(
    app_name: str,
    owner: str,
    redirect_url: str,
    refresh: bool = False,
    app_id: Optional[str] = None,
    refresh_token_expire_hours: int = 24,
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
    )
    if refresh:
        app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
        app.refresh_token_expire_hours = refresh_token_expire_hours

    app.set_key(key)
    await app.insert()

    return app
