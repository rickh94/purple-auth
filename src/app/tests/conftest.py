import uuid
import jwcrypto.jwk as jwk

import pytest
from fastapi.testclient import TestClient

from app.io.models import ClientApp
from app.main import app


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def create_fake_client_app(faker):
    def _create(app_id=None, refresh=False, refresh_expire=None):
        if not app_id:
            app_id = str(uuid.uuid4())
        key = jwk.JWK.generate(kty="EC", size=2048)
        refresh_key = None
        refresh_token_expire_hours = None
        if refresh:
            refresh_key = jwk.JWK.generate(kty="EC", size=4096)
            refresh_token_expire_hours = refresh_expire or 24
        return ClientApp(
            name=faker.company(),
            app_id=app_id,
            refresh_key=refresh_key,
            refresh_token_expire_hours=refresh_token_expire_hours,
            key=key.export_private(as_dict=True),
            redirect_url="http://localhost",
        )

    return _create


@pytest.fixture
def fake_client_app(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app()

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
def fake_email(faker):
    return faker.email()


@pytest.fixture
def fake_app_id():
    return uuid.uuid4()
