import asyncio
import secrets
import uuid
from typing import Optional
import jwcrypto.jwk as jwk

import click

from app import config
from app.models.client_app_model import ClientApp
from app.portal.crud import clientapp_crud


@click.group()
def cli():
    pass


@cli.command()
@click.argument("app_name")
@click.option("-u", "--url", prompt=True)
@click.option("-r", "--refresh", is_flag=True)
@click.option("--refresh-token-expire-hours", type=int)
@click.option("--app-id")
@click.option("--api-key")
def createapp(
    app_name: str,
    url: str,
    refresh: bool,
    refresh_token_expire_hours: Optional[int],
    app_id: Optional[str],
    api_key: Optional[str],
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
    if not api_key:
        api_key = secrets.token_urlsafe()
    app.set_api_key(api_key)
    asyncio.run(app.insert())
    print(f"New App ID: {app_id}")
    print(f"API Key: {api_key}")


@cli.command()
@click.argument("app_id")
def reset_api_key(app_id: str):
    app = asyncio.run(ClientApp.query(ClientApp.app_id == app_id).get())
    api_key = secrets.token_urlsafe()
    app.set_api_key(api_key)
    asyncio.run(app.save())
    print(f"New API Key: {api_key}")


if __name__ == "__main__":
    cli()
