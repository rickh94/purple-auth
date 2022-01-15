import asyncio
import uuid
from typing import Optional
from urllib.parse import quote_plus
import jwcrypto.jwk as jwk

import click

from app import config
from app.models.client_app_model import ClientApp


@click.group()
def cli():
    pass


@cli.command()
@click.argument("app_name")
@click.option("-u", "--url", prompt=True)
@click.option("-r", "--refresh", is_flag=True)
@click.option("--refresh-token-expire-hours", type=int)
@click.option("--app-id")
def createapp(
    app_name: str,
    url: str,
    refresh: bool,
    refresh_token_expire_hours: Optional[int],
    app_id: Optional[str],
):
    key = jwk.JWK.generate(kty="EC", size=2048)
    app_id = app_id or str(uuid.uuid4())
    app = ClientApp(
        name=app_name,
        app_id=app_id,
        key=None,
        refresh_key=None,
        refresh_token_expire_hours=None,
        redirect_url=url,
        owner=config.WEBMASTER_EMAIL,
    )
    if refresh:
        app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
        app.refresh_token_expire_hours = refresh_token_expire_hours or 24
    app.set_key(key)
    asyncio.run(app.insert())
    print(app_id)


if __name__ == "__main__":
    cli()
