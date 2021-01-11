import uuid
from urllib.parse import quote_plus

import jwcrypto.jwk as jwk
import pymongo

import pytest
from faker import Faker
from fastapi.testclient import TestClient
from motor import motor_asyncio
from odmantic import AIOEngine
from passlib.context import CryptContext

from app import config
from app.io.models import ClientApp
from app.main import app


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def create_fake_client_app(faker):
    def _create(
        app_id=None, refresh=False, refresh_expire=None, failure_redirect_url=None
    ):
        if not app_id:
            app_id = str(uuid.uuid4())
        key = jwk.JWK.generate(kty="EC", size=2048)
        _app = ClientApp(
            name=faker.company(),
            app_id=app_id,
            refresh_key=None,
            refresh_token_expire_hours=None,
            key=None,
            redirect_url="http://localhost",
            failure_redirect_url=failure_redirect_url,
        )
        _app.set_key(key)
        if refresh:
            _app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
            _app.refresh_token_expire_hours = refresh_expire or 24
        return _app

    return _create


@pytest.fixture
def fake_client_app(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app()

    async def _engine_fake_get(*args):
        return _fake

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)

    return _fake


@pytest.fixture
def fake_refresh_client_app(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app(refresh=True)

    async def _engine_fake_get(*args):
        return _fake

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)

    return _fake


@pytest.fixture
def app_not_found(monkeypatch):
    async def _no_app(*args):
        return None

    monkeypatch.setattr("app.dependencies.engine.find_one", _no_app)


@pytest.fixture
def fake_email():
    return Faker().email()


@pytest.fixture
def fake_app_id():
    return uuid.uuid4()


@pytest.fixture
def pwd_context():
    return CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
