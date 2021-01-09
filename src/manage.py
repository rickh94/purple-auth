import os
import uuid
from typing import Optional
from urllib.parse import quote_plus
import jwcrypto.jwk as jwk

import pymongo
import click

from app import config
from app.io.models import ClientApp

db_uri = "mongodb://{username}:{password}@{host}:{port}".format(
    username=quote_plus(config.DB_USERNAME),
    password=quote_plus(config.DB_PASSWORD),
    host=quote_plus(config.DB_HOST),
    port=quote_plus(config.DB_PORT),
)

db_client = pymongo.MongoClient(db_uri)
db = db_client[config.DB_NAME]


@click.group()
def cli():
    pass


@cli.command()
@click.argument("app_name")
@click.option("-u", "--url", prompt=True)
@click.option("-r", "--refresh", is_flag=True)
@click.option("--refresh-token-expire-hours", type=int)
def createapp(
    app_name: str, url: str, refresh: bool, refresh_token_expire_hours: Optional[int]
):
    key = jwk.JWK.generate(kty="EC", size=2048)
    app_id = str(uuid.uuid4())
    refresh_key = None
    if refresh:
        refresh_key = jwk.JWK.generate(kty="EC", size=4096).export_private(as_dict=True)
        refresh_token_expire_hours = refresh_token_expire_hours or 24
    app = ClientApp(
        name=app_name,
        app_id=app_id,
        key=key.export_private(as_dict=True),
        refresh_key=refresh_key,
        refresh_token_expire_hours=refresh_token_expire_hours,
        redirect_url=url,
    )
    db.client_app.insert_one(app.dict())
    print(app_id)


if __name__ == "__main__":
    cli()
