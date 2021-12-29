import datetime
import secrets
import string

from app import config
from app.io.redis_interface import OTP_STORE
from app.security.context import PWD_CONTEXT


def generate(email: str, app_id: str) -> str:
    code = "".join(secrets.choice(string.digits) for _ in range(config.OTP_LENGTH))
    code_hash = PWD_CONTEXT.hash(code)
    OTP_STORE.set(f"{app_id}:otp:{email}", code_hash)
    OTP_STORE.expire(
        f"{app_id}:otp:{email}", datetime.timedelta(minutes=config.OTP_LIFETIME)
    )
    return code


def verify(email: str, code: str, app_id: str) -> bool:
    code_hash = OTP_STORE.get(f"{app_id}:otp:{email}")
    if PWD_CONTEXT.verify(code, code_hash):
        OTP_STORE.expire(f"{app_id}:otp:{email}", datetime.timedelta(seconds=1))
        return True
    return False
