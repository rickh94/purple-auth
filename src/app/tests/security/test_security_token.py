import datetime
import time
import uuid
from unittest.mock import AsyncMock

import pytest
from faker import Faker
from odmantic import AIOEngine

from app import config
from app.dependencies import engine
from app.io.models import RefreshToken, ClientApp
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


@pytest.mark.asyncio
async def test_generate_refresh_token(
    fake_email,
    fake_refresh_client_app: ClientApp,
    monkeypatch,
    mocker,
    pwd_context,
):
    monkeypatch.setattr(uuid, "uuid4", lambda: "fake_uuid")
    mock_engine = mocker.patch("app.security.token.engine", new_callable=AsyncMock)
    refresh_token = await security_token.generate_refresh_token(
        fake_email, fake_refresh_client_app
    )
    assert refresh_token is not None

    headers, claims = jwt.verify_jwt(
        refresh_token, fake_refresh_client_app.get_refresh_key(), allowed_algs=["ES256"]
    )

    assert headers["alg"] == "ES256"
    assert claims["sub"] == fake_email
    assert claims["iss"] == f"{config.ISSUER}/{fake_refresh_client_app.app_id}"
    assert claims["uid"] == "fake_uuid"

    mock_engine.save.assert_called()
    # getting the seconds just right is annoying, so it's easiest just to check that
    # it's within about 10 minutes of the correct time.
    should_expire_lower_bound = (
        datetime.datetime.now()
        + datetime.timedelta(hours=fake_refresh_client_app.refresh_token_expire_hours)
        - datetime.timedelta(minutes=5)
    )
    should_expire_upper_bound = (
        datetime.datetime.now()
        + datetime.timedelta(hours=fake_refresh_client_app.refresh_token_expire_hours)
        + datetime.timedelta(minutes=5)
    )
    generated_rt: RefreshToken = mock_engine.save.call_args[0][0]

    assert isinstance(generated_rt, RefreshToken)
    assert generated_rt.email == fake_email
    assert generated_rt.app_id == fake_refresh_client_app.app_id
    assert generated_rt.expires >= should_expire_lower_bound
    assert generated_rt.expires <= should_expire_upper_bound
    assert generated_rt.uid == "fake_uuid"
    assert pwd_context.verify(refresh_token, generated_rt.hash)
