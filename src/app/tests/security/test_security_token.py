import datetime
import time
import uuid
from unittest import mock
from unittest.mock import AsyncMock

import pytest

from app import config
from app.models.client_app_model import ClientApp
from app.models.token_models import RefreshToken
from app.security import token as security_token
from jwcrypto import jwk
import python_jwt as jwt


@pytest.fixture
def fake_uid():
    return str(uuid.uuid4())


@pytest.fixture
def fake_refresh_token(fake_refresh_client_app, fake_email, pwd_context, fake_uid):
    payload = {
        "iss": f"{config.ISSUER}/{fake_refresh_client_app.app_id}",
        "sub": fake_email,
        "uid": fake_uid,
    }
    refresh_token = jwt.generate_jwt(
        payload,
        fake_refresh_client_app.get_refresh_key(),
        "ES256",
        datetime.timedelta(hours=fake_refresh_client_app.refresh_token_expire_hours),
    )
    return refresh_token


@pytest.fixture
def saved_refresh_token(
    fake_refresh_token,
    fake_refresh_client_app,
    fake_email,
    pwd_context,
    monkeypatch,
    fake_uid,
):
    expires = datetime.datetime.now() + datetime.timedelta(hours=24)
    _saved = RefreshToken(
        app_id=fake_refresh_client_app.app_id,
        email=fake_email,
        hash=pwd_context.hash(fake_refresh_token),
        expires=expires,
        uid=fake_uid,
    )

    async def _get_saved(*args):
        return _saved

    monkeypatch.setattr("app.security.token.engine.find_one", _get_saved)
    return _saved


@pytest.fixture
def generate_saved_refresh_token(fake_refresh_client_app, fake_email, pwd_context):
    def _generate():
        uid = str(uuid.uuid4())
        payload = {
            "iss": f"{config.ISSUER}/{fake_refresh_client_app.app_id}",
            "sub": fake_email,
            "uid": uid,
        }
        refresh_token = jwt.generate_jwt(
            payload,
            fake_refresh_client_app.get_refresh_key(),
            "ES256",
            datetime.timedelta(
                hours=fake_refresh_client_app.refresh_token_expire_hours
            ),
        )
        expires = datetime.datetime.now() + datetime.timedelta(hours=24)
        _saved = RefreshToken(
            app_id=fake_refresh_client_app.app_id,
            email=fake_email,
            hash=pwd_context.hash(refresh_token),
            expires=expires,
            uid=uid,
        )

        return _saved

    return _generate


def test_generate(fake_email, fake_client_app):
    token = security_token.generate(fake_email, fake_client_app)
    assert token is not None

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


@pytest.mark.asyncio
async def test_generate_refresh_token_invalid_app(
    fake_email,
    fake_client_app: ClientApp,
    monkeypatch,
    mocker,
):
    monkeypatch.setattr(uuid, "uuid4", lambda: "fake_uuid")
    mock_engine = mocker.patch("app.security.token.engine", new_callable=AsyncMock)

    with pytest.raises(security_token.TokenCreationError):
        await security_token.generate_refresh_token(fake_email, fake_client_app)

    mock_engine.save.assert_not_called()


@pytest.mark.asyncio
async def test_verify_refresh_token(
    fake_refresh_client_app: ClientApp, fake_refresh_token, saved_refresh_token
):
    result = await security_token.verify_refresh_token(
        fake_refresh_token, fake_refresh_client_app
    )

    assert result is not None


@pytest.mark.asyncio
async def test_verify_refresh_token_not_found(
    fake_refresh_client_app: ClientApp, monkeypatch, fake_refresh_token
):
    async def _get_saved(*args):
        return None

    monkeypatch.setattr("app.security.token.engine.find_one", _get_saved)

    with pytest.raises(security_token.TokenVerificationError):
        await security_token.verify_refresh_token(
            fake_refresh_token, fake_refresh_client_app
        )


@pytest.mark.asyncio
async def test_verify_refresh_token_expired_token(
    fake_email, fake_refresh_client_app: ClientApp, monkeypatch, pwd_context
):
    uid = "fake_uuid"
    expires = datetime.datetime.now() + datetime.timedelta(hours=24)
    payload = {
        "iss": f"{config.ISSUER}/{fake_refresh_client_app.app_id}",
        "sub": fake_email,
        "uid": uid,
    }
    refresh_token = jwt.generate_jwt(
        payload,
        fake_refresh_client_app.get_refresh_key(),
        "ES256",
        datetime.timedelta(seconds=0),
    )
    saved_refresh_token = RefreshToken(
        app_id=fake_refresh_client_app.app_id,
        email=fake_email,
        hash=pwd_context.hash(refresh_token),
        expires=expires,
        uid=uid,
    )

    async def _get_saved(*args):
        return saved_refresh_token

    monkeypatch.setattr("app.security.token.engine.find_one", _get_saved)

    with pytest.raises(security_token.TokenVerificationError):
        await security_token.verify_refresh_token(
            refresh_token, fake_refresh_client_app
        )


@pytest.mark.asyncio
async def test_verify_refresh_token_expired_in_database(
    fake_email,
    fake_refresh_client_app: ClientApp,
    monkeypatch,
    pwd_context,
    mocker,
    fake_refresh_token,
):
    mock_delete = mocker.patch(
        "app.security.token.engine.delete", new_callable=AsyncMock
    )
    expires = datetime.datetime.now() - datetime.timedelta(hours=24)
    saved_refresh_token = RefreshToken(
        app_id=fake_refresh_client_app.app_id,
        email=fake_email,
        hash=pwd_context.hash(fake_refresh_token),
        expires=expires,
        uid="fake_uuid",
    )

    async def _get_saved(*args):
        return saved_refresh_token

    monkeypatch.setattr("app.security.token.engine.find_one", _get_saved)

    with pytest.raises(security_token.TokenVerificationError):
        await security_token.verify_refresh_token(
            fake_refresh_token, fake_refresh_client_app
        )
    mock_delete.assert_called()


@pytest.mark.asyncio
async def test_verify_refresh_token_pwd_verification_failed(
    fake_email,
    fake_refresh_client_app: ClientApp,
    monkeypatch,
    pwd_context,
    fake_refresh_token,
):
    saved_refresh_token = RefreshToken(
        app_id=fake_refresh_client_app.app_id,
        email=fake_email,
        hash=pwd_context.hash(
            f"{fake_refresh_token}this should produce a different hash"
        ),
        expires=datetime.datetime.now() + datetime.timedelta(hours=24),
        uid="fake_uuid",
    )

    async def _get_saved(*args):
        return saved_refresh_token

    monkeypatch.setattr("app.security.token.engine.find_one", _get_saved)

    with pytest.raises(security_token.TokenVerificationError):
        await security_token.verify_refresh_token(
            fake_refresh_token, fake_refresh_client_app
        )


@pytest.mark.asyncio
async def test_delete_refresh_token(
    fake_refresh_client_app: ClientApp,
    mocker,
    fake_refresh_token,
    saved_refresh_token,
):
    fake_delete: mock.MagicMock = mocker.patch("app.security.token.engine.delete")

    await security_token.delete_refresh_token(
        fake_refresh_token, fake_refresh_client_app
    )

    fake_delete.assert_called_once_with(saved_refresh_token)


@pytest.mark.asyncio
async def test_delete_refresh_token_not_found(
    fake_refresh_client_app: ClientApp,
    monkeypatch,
    mocker,
    fake_refresh_token,
):
    async def _get_saved(*args):
        return None

    monkeypatch.setattr("app.security.token.engine.find_one", _get_saved)
    fake_delete: mock.MagicMock = mocker.patch("app.security.token.engine.delete")

    with pytest.raises(security_token.TokenVerificationError):
        await security_token.verify_refresh_token(
            fake_refresh_token, fake_refresh_client_app
        )

    fake_delete.assert_not_called()


@pytest.mark.asyncio
async def test_delete_all_refresh_tokens(
    fake_refresh_client_app,
    monkeypatch,
    mocker,
    generate_saved_refresh_token,
    fake_email,
):
    tokens = [generate_saved_refresh_token() for _ in range(10)]

    class FakeResults:
        def __init__(self, tokens):
            self.tokens = tokens
            self.i = 0

        def __aiter__(self):
            return self

        async def __anext__(self):
            i = self.i
            if i >= len(self.tokens):
                raise StopAsyncIteration
            self.i += 1
            return self.tokens[i]

    def _find(*args):
        return FakeResults(tokens)

    monkeypatch.setattr("app.security.token.engine.find", _find)
    fake_delete: mock.MagicMock = mocker.patch("app.security.token.engine.delete")

    await security_token.delete_all_refresh_tokens(fake_email, fake_refresh_client_app)

    for i, token in enumerate(tokens):
        fake_delete.assert_any_call(token)
