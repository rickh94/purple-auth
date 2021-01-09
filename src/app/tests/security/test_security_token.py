import datetime
import time
import uuid

import pytest

from app import config
from app.security import token as security_token
from jwcrypto import jwk
import python_jwt as jwt


def test_generate(fake_email, fake_client_app):
    token = security_token.generate(fake_email, fake_client_app)
    assert token is not None

    # key = jwk.JWK(**fake_client_app.key)
    headers, claims = jwt.verify_jwt(
        token, fake_client_app.get_key(), allowed_algs=["ES256"]
    )

    assert headers["alg"] == "ES256"
    assert claims["sub"] == fake_email
    assert claims["iss"] == f"{config.ISSUER}/{fake_client_app.app_id}"


def test_verify(fake_email, fake_client_app):
    token = security_token.generate(fake_email, fake_client_app)
    headers, claims = security_token.verify(token, fake_client_app)

    assert headers["alg"] == "ES256"
    assert claims["sub"] == fake_email
    assert claims["iss"] == f"{config.ISSUER}/{fake_client_app.app_id}"
    assert claims.get("iat") is not None
    assert claims.get("exp") is not None


def test_verify_wrong_app_fails(fake_email, fake_client_app, create_fake_client_app):
    fake_client_app2 = create_fake_client_app()
    token = security_token.generate(fake_email, fake_client_app)

    with pytest.raises(security_token.TokenVerificationError):
        security_token.verify(token, fake_client_app2)


def test_verify_wrong_key_fails(fake_email, fake_client_app):
    key = jwk.JWK.generate(kty="EC", size=2048)
    payload = {"iss": f"{config.ISSUER}/12345", "sub": fake_email}
    token = jwt.generate_jwt(
        payload,
        key,
        "ES256",
        datetime.timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    with pytest.raises(security_token.TokenVerificationError):
        security_token.verify(token, fake_client_app)


def test_verify_expired_fails(fake_email, fake_client_app):
    payload = {"iss": f"{config.ISSUER}/{fake_client_app.app_id}", "sub": fake_email}
    token = jwt.generate_jwt(
        payload,
        fake_client_app.get_key(),
        "ES256",
        datetime.timedelta(seconds=1),
    )
    time.sleep(1)

    with pytest.raises(security_token.TokenVerificationError):
        security_token.verify(token, fake_client_app)


def test_verify_ridiculous_token_fails(fake_client_app):
    with pytest.raises(security_token.TokenVerificationError):
        security_token.verify("not-even-a-real-token", fake_client_app)


def test_verify_invalid_token_fails(fake_client_app):
    with pytest.raises(security_token.TokenVerificationError):
        security_token.verify("fakeheaders.fakeclaims.whoknows", fake_client_app)


def test_verify_wrong_issuer_domain_fails(fake_email, fake_client_app):
    payload = {
        "iss": f"https://example.com/{fake_client_app.app_id}",
        "sub": fake_email,
    }
    # key = jwk.JWK(**fake_client_app.key)
    token = jwt.generate_jwt(
        payload,
        fake_client_app.get_key(),
        "ES256",
        datetime.timedelta(seconds=1),
    )

    with pytest.raises(security_token.TokenVerificationError):
        security_token.verify(token, fake_client_app)


def test_verify_wrong_issuer_app_id_fails(fake_email, fake_client_app):
    payload = {"iss": f"{config.ISSUER}/{uuid.uuid4()}", "sub": fake_email}
    # key = jwk.JWK(**fake_client_app.key)
    token = jwt.generate_jwt(
        payload,
        fake_client_app.get_key(),
        "ES256",
        datetime.timedelta(seconds=1),
    )

    with pytest.raises(security_token.TokenVerificationError):
        security_token.verify(token, fake_client_app)
