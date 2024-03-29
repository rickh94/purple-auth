import datetime
import uuid

import mongox
import python_jwt as jwt
from fastapi import Header, Depends, HTTPException
from jwcrypto.jws import InvalidJWSObject, InvalidJWSSignature

from app import config
from app.dependencies import check_client_app
from app.models.client_app_model import ClientApp
from app.models.token_models import RefreshToken
from app.security.context import PWD_CONTEXT


class TokenVerificationError(BaseException):
    pass


class TokenCreationError(BaseException):
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
    if claims["iss"] != f"{config.ISSUER}/app/{app_id}":
        raise TokenVerificationError
    return headers, claims


def generate(email: str, client_app: ClientApp) -> str:
    payload = {"iss": f"{config.ISSUER}/app/{client_app.app_id}", "sub": email}
    return jwt.generate_jwt(
        payload,
        client_app.get_key(),
        "ES256",
        datetime.timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def verify(token: str, client_app: ClientApp) -> (dict, dict):
    return _check_token(token, client_app.get_key(), client_app.app_id)


async def generate_refresh_token(email: str, client_app: ClientApp) -> str:
    if not client_app.get_refresh_key() or not client_app.refresh_token_expire_hours:
        raise TokenCreationError("Refresh is not enabled")
    uid = str(uuid.uuid4())
    payload = {
        "iss": f"{config.ISSUER}/app/{client_app.app_id}",
        "sub": email,
        "uid": uid,
    }
    token = jwt.generate_jwt(
        payload,
        client_app.get_refresh_key(),
        "ES256",
        datetime.timedelta(hours=client_app.refresh_token_expire_hours),
    )
    token_hash = PWD_CONTEXT.hash(token)
    expires = datetime.datetime.now() + datetime.timedelta(
        hours=client_app.refresh_token_expire_hours
    )
    await RefreshToken(
        app_id=client_app.app_id,
        email=email,
        hash=token_hash,
        expires=expires,
        uid=uid,
    ).insert()
    return token


async def _find_refresh_token(claims: dict, client_app: ClientApp):
    try:
        return (
            await RefreshToken.query(RefreshToken.email == claims["sub"])
            .query(RefreshToken.app_id == client_app.app_id)
            .query(RefreshToken.uid == claims["uid"])
            .get()
        )
    except mongox.NoMatchFound:
        raise TokenVerificationError("Could not find matching token.")
    except mongox.MultipleMatchesFound:
        raise TokenVerificationError("Something has gone wrong")


async def verify_refresh_token(token: str, client_app: ClientApp) -> str:
    _, claims = _check_token(token, client_app.get_refresh_key(), client_app.app_id)
    found_rt = await _find_refresh_token(claims, client_app)
    if found_rt.expires <= datetime.datetime.now():
        await found_rt.delete()
        raise TokenVerificationError("Expired Token. Please log in again.")
    if PWD_CONTEXT.verify(token, found_rt.hash):
        return generate(claims["sub"], client_app)
    raise TokenVerificationError("Could not find matching refresh token")


async def delete_refresh_token(refresh_token: str, client_app: ClientApp):
    _, claims = _check_token(
        refresh_token, client_app.get_refresh_key(), client_app.app_id
    )
    found_rt = await _find_refresh_token(claims, client_app)
    await found_rt.delete()


async def delete_all_refresh_tokens(email: str, client_app: ClientApp):
    for rt in (
        await RefreshToken.query(RefreshToken.email == email)
        .query(RefreshToken.app_id == client_app.app_id)
        .all()
    ):
        await rt.delete()


async def authorization_header(
    authorization: str = Header(...), client_app: ClientApp = Depends(check_client_app)
) -> dict:
    if "Bearer" not in authorization:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    token = authorization.replace("Bearer ", "")
    try:
        headers, claims = verify(token, client_app)
    except TokenVerificationError:
        raise HTTPException(status_code=401, detail=f"Invalid Token")
    return {
        "headers": headers,
        "claims": claims,
    }
