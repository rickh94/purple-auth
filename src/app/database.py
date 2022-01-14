from urllib.parse import quote_plus

import mongox

from app import config
from app.config import DB_URL

if not DB_URL:
    DB_URL = "mongodb://{username}:{password}@{host}:{port}".format(
        username=quote_plus(config.DB_USERNAME),
        password=quote_plus(config.DB_PASSWORD),
        host=quote_plus(config.DB_HOST),
        port=quote_plus(config.DB_PORT),
    )

db_client = mongox.Client(DB_URL)
db = db_client.get_database("purple_auth")
