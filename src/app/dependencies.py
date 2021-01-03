from urllib.parse import quote_plus

from motor import motor_asyncio
from odmantic import AIOEngine

from app import config

db_uri = "mongodb://{username}:{password}@{host}:{port}".format(
    username=quote_plus(config.DB_USERNAME),
    password=quote_plus(config.DB_PASSWORD),
    host=quote_plus(config.DB_HOST),
    port=quote_plus(config.DB_PORT),
)

db_client = motor_asyncio.AsyncIOMotorClient(db_uri)
engine = AIOEngine(motor_client=db_client, database=config.DB_NAME)
