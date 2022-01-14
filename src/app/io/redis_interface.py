from redis import Redis
from app import config

if config.REDIS_URL:
    OTP_STORE = Redis.from_url(f"{config.REDIS_URL}/0")
    MAGIC_STORE = Redis.from_url(f"{config.REDIS_URL}/1")
else:
    OTP_STORE = Redis(
        host=config.REDIS_HOST,
        port=config.REDIS_PORT,
        db=0,
        password=config.REDIS_PASSWORD,
    )
    MAGIC_STORE = Redis(
        host=config.REDIS_HOST,
        port=config.REDIS_PORT,
        db=1,
        password=config.REDIS_PASSWORD,
    )
