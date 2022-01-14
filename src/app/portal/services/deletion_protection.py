import datetime
import secrets
import string

from redis import Redis

from app import config
from app.portal.models.user_model import User
from app.security.context import PWD_CONTEXT

if config.REDIS_URL:
    DP_CODE_STORE = Redis.from_url(f"{config.REDIS_URL}/10")
else:
    DP_CODE_STORE = Redis(
        host=config.REDIS_HOST,
        port=config.REDIS_PORT,
        db=10,
        password=config.REDIS_PASSWORD,
    )


def generate_dp_code(user: User, delete_id: str) -> str:
    """
    Generate a verification code for deletion protection and store it in redis.

    :param user: the user requesting the code
    :param delete_id: the app_id of the app to delete or "account" if they are
    deleting their account
    :return: the verification code
    """
    code = "".join(secrets.choice(string.digits) for _ in range(config.OTP_LENGTH))
    code_hash = PWD_CONTEXT.hash(code)
    DP_CODE_STORE.set(f"{user.email}:{delete_id}", code_hash)
    DP_CODE_STORE.expire(
        f"{user.email}:{delete_id}", datetime.timedelta(minutes=config.OTP_LIFETIME)
    )
    return code


def verify_dp_code(user: User, delete_id: str, code: str) -> bool:
    """
    Verify a deletion protection code against the hash stored in redis.

    :param user: the user requesting the code
    :param delete_id: the app_id of the app to delete or "account" if they are deleting
    their account.
    :param code:
    :return: True if the code is valid, false otherwise
    """
    code_hash = DP_CODE_STORE.get(f"{user.email}:{delete_id}")
    if PWD_CONTEXT.verify(code, code_hash):
        DP_CODE_STORE.expire(f"{user.email}:{delete_id}", datetime.timedelta(seconds=1))
        return True
    return False
