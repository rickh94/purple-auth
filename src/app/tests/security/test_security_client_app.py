import datetime

import pytest
from jwcrypto import jwk
import python_jwt as jwt
from jwcrypto.jws import InvalidJWSSignature

from app import config
from app.security import client_app as security_client_app, token as security_token


def test_export_public_key(fake_client_app):
    exported_key_dict = security_client_app.export_public_key(fake_client_app)
    assert isinstance(exported_key_dict, dict)

    # check that the exported key can be used to create a new JWK object
    # (and is therefore valid)
    exported_key = jwk.JWK(**exported_key_dict)
    assert exported_key is not None


def test_exported_key_verifies_token(fake_client_app, fake_email):
    token = security_token.generate(fake_email, fake_client_app)
    exported_key_dict = security_client_app.export_public_key(fake_client_app)
    key = jwk.JWK(**exported_key_dict)

    headers, claims = jwt.verify_jwt(token, key, allowed_algs=["ES256"])

    assert headers["alg"] == "ES256"
    assert claims["sub"] == fake_email
    assert claims["iss"] == f"{config.ISSUER}/{fake_client_app.app_id}"


def test_exported_key_doesnt_verify_invalid_token(
    fake_client_app, fake_email, create_fake_client_app
):
    fake_client_app2 = create_fake_client_app()
    token = security_token.generate(fake_email, fake_client_app)
    exported_key_dict = security_client_app.export_public_key(fake_client_app2)
    key = jwk.JWK(**exported_key_dict)

    assert fake_client_app.get_key() != fake_client_app2.get_key()
    with pytest.raises(InvalidJWSSignature):
        jwt.verify_jwt(token, key, allowed_algs=["ES256"])


def test_exported_key_cannot_sign_keys(fake_client_app, fake_email):
    exported_key_dict = security_client_app.export_public_key(fake_client_app)
    exported_key = jwk.JWK(**exported_key_dict)
    payload = {"iss": f"{config.ISSUER}/12345", "sub": fake_email}

    token = None
    with pytest.raises(TypeError):
        token = jwt.generate_jwt(
            payload,
            exported_key,
            "ES256",
            datetime.timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
    assert token is None
