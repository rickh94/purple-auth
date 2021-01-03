import os
import uuid
from urllib.parse import quote_plus
import jwcrypto.jwk as jwk

import pymongo
import click

from app import config
from app.io.models import App

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
def createapp(app_name: str):
    key = jwk.JWK.generate(kty='EC', size=2048)
    app_id = str(uuid.uuid4())
    app = App(name=app_name, app_id=app_id, key=key.export())
    db.app.insert_one(app.dict())
    return app_id


if __name__ == '__main__':
    cli()
