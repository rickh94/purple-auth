import datetime
import uuid

import jwcrypto.jwk as jwk
import python_jwt as jwt
from jwcrypto.jws import InvalidJWSObject, InvalidJWSSignature
from passlib.context import CryptContext

from app import config
from app.dependencies import engine
from app.io.models import ClientApp, RefreshToken


class TokenVerificationError(BaseException):
    pass


def _check_token(token, key, app_id) -> (dict, dict):
    try:
        headers, claims = jwt.verify_jwt(token, key, allowed_algs=["ES256"])
    except (
        jwt._JWTError,
        UnicodeDecodeError,
        InvalidJWSObject,
        InvalidJWSSignature,
        ValueError,
    ):
        raise TokenVerificationError
    if claims["iss"] != f"{config.ISSUER}/{app_id}":
        raise TokenVerificationError
    return headers, claims


def generate(email: str, client_app: ClientApp) -> str:
    key = jwk.JWK(**client_app.key)
    payload = {"iss": f"{config.ISSUER}/{client_app.app_id}", "sub": email}
    return jwt.generate_jwt(
        payload,
        key,
        "ES256",
        datetime.timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def verify(token: str, client_app: ClientApp) -> (dict, dict):
    key = jwk.JWK(**client_app.key)
    return _check_token(token, key, client_app.app_id)


PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def generate_refresh_token(email: str, client_app: ClientApp) -> str:
    key = jwk.JWK(**client_app.refresh_key)
    uid = str(uuid.uuid4())
    payload = {"iss": f"{config.ISSUER}/{client_app.app_id}", "sub": email, "uid": uid}
    token = jwt.generate_jwt(
        payload,
        key,
        "ES256",
        datetime.timedelta(hours=client_app.refresh_token_expire_hours),
    )
    token_hash = PWD_CONTEXT.hash(token)
    expires = datetime.datetime.now() + datetime.timedelta(
        hours=client_app.refresh_token_expire_hours
    )
    save_token = RefreshToken(
        app_id=client_app.app_id,
        email=email,
        hash=token_hash,
        expires=expires,
        uid=uid,
    )
    await engine.save(save_token)
    return token


async def verify_refresh_token(token: str, client_app: ClientApp) -> str:
    key = jwk.JWK(**client_app.refresh_key)
    headers, claims = _check_token(token, key, client_app.app_id)
    found_rt = await engine.find_one(
        RefreshToken,
        (RefreshToken.email == claims["sub"])
        & (RefreshToken.app_id == client_app.app_id)
        & (RefreshToken.uid == claims["uid"]),
    )
    if found_rt.expires <= datetime.datetime.now():
        await engine.delete(found_rt)
        raise TokenVerificationError("Expired Token. Please log in again.")
    if PWD_CONTEXT.verify(token, found_rt.hash):
        return generate(claims["sub"], client_app)
    raise TokenVerificationError("Could not find matching refresh token")
