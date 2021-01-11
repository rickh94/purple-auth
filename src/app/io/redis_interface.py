from redis import Redis
from app import config

OTP_STORE = Redis(
    host=config.REDIS_HOST, port=config.REDIS_PORT, db=0, password=config.REDIS_PASSWORD
)

MAGIC_STORE = Redis(
    host=config.REDIS_HOST, port=config.REDIS_PORT, db=1, password=config.REDIS_PASSWORD
)
