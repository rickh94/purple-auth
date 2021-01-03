from redis import Redis
from app import config

OTP_STORE = Redis(
    host=config.REDIS_PORT,
    port=config.REDIS_PORT,
    db=0,
    password=config.REDIS_PASSWORD,
)
