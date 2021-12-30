from urllib.parse import quote_plus

import mongox

from app import config

db_uri = "mongodb://{username}:{password}@{host}:{port}".format(
    username=quote_plus(config.DB_USERNAME),
    password=quote_plus(config.DB_PASSWORD),
    host=quote_plus(config.DB_HOST),
    port=quote_plus(config.DB_PORT),
)

db_client = mongox.Client(db_uri)
db = db_client.get_database("purple_auth")
