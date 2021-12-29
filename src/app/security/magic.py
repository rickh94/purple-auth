import datetime
import secrets
from typing import Optional
from urllib.parse import quote_plus, unquote

from app import config
from app.io.redis_interface import MAGIC_STORE
from app.security.context import PWD_CONTEXT


def generate(email: str, app_id: str) -> str:
    url_secret = secrets.token_urlsafe()
    secret_hash = PWD_CONTEXT.hash(url_secret)
    MAGIC_STORE.set(f"{app_id}:magic:{email}", secret_hash)
    MAGIC_STORE.expire(
        f"{app_id}:magic:{email}", datetime.timedelta(minutes=config.MAGIC_LIFETIME)
    )
    enc_email = config.FERNET.encrypt(email.encode("utf-8"))
    return (
        f"{config.HOST}/magic/confirm/{app_id}?secret={url_secret}"
        f"&id={quote_plus(enc_email)}"
    )


def verify(enc_email: str, secret: str, app_id: str) -> Optional[str]:
    email = config.FERNET.decrypt(unquote(enc_email).encode("utf-8")).decode("utf-8")
    secret_hash = MAGIC_STORE.get(f"{app_id}:magic:{email}")
    if PWD_CONTEXT.verify(secret, secret_hash):
        MAGIC_STORE.expire(f"{app_id}:magic:{email}", datetime.timedelta(seconds=1))
        return email
    return None
