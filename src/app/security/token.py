import datetime

import jwcrypto.jwk as jwk
import python_jwt as jwt
from jwcrypto.jws import InvalidJWSObject, InvalidJWSSignature

from app import config
from app.io.models import ClientApp


def generate(email: str, client_app: ClientApp):
    key = jwk.JWK(**client_app.key)
    payload = {"iss": f"{config.ISSUER}/{client_app.app_id}", "sub": email}
    return jwt.generate_jwt(
        payload,
        key,
        "ES256",
        datetime.timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


class TokenVerificationError(Exception):
    pass


def verify(client_app: ClientApp, token: str):
    key = jwk.JWK(**client_app.key)
    # noinspection PyProtectedMember
    try:
        headers, claims = jwt.verify_jwt(token, key, allowed_algs=["ES256"])
    except (
        jwt._JWTError,
        UnicodeDecodeError,
        InvalidJWSObject,
        InvalidJWSSignature,
    ) as e:
        raise TokenVerificationError(e)
    if claims["iss"] != f"{config.ISSUER}/{client_app.app_id}":
        raise TokenVerificationError("Issue does not match")
    return headers, claims
