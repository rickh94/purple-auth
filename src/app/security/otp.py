import datetime
import secrets
import string

from passlib.context import CryptContext

from app import config
from app.io.redis_interface import OTP_STORE

PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")


def generate(email: str) -> str:
    code = "".join(secrets.choice(string.digits) for _ in range(config.OTP_LENGTH))
    code_hash = PWD_CONTEXT.hash(code)
    OTP_STORE.set(f"otp:{email}", code_hash)
    OTP_STORE.expire(f"otp:{email}", datetime.timedelta(minutes=config.OTP_LIFETIME))
    return code


def verify(email: str, code: str) -> bool:
    code_hash = OTP_STORE.get(f"otp:{email}")
    if PWD_CONTEXT.verify(code, code_hash):
        OTP_STORE.expire(f"otp:{email}", datetime.timedelta(seconds=1))
        return True
    return False
