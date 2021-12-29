import datetime
import uuid

import jwcrypto.jwk as jwk
import pytest
from faker import Faker
from fastapi.testclient import TestClient

from app.models.client_app_model import ClientApp
from app.main import app
from app.security.context import PWD_CONTEXT


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def create_fake_client_app(faker):
    def _create(
        app_id=None,
        refresh=False,
        refresh_expire=None,
        failure_redirect_url=None,
        owner=None,
        quota=500,
        low_quota_threshold=10,
        low_quota_last_notified=None,
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
            owner=owner,
            quota=quota,
            low_quota_threshold=low_quota_threshold,
        )
        if low_quota_last_notified:
            _app.low_quota_last_notified = low_quota_last_notified
        _app.set_key(key)
        if refresh:
            _app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
            _app.refresh_token_expire_hours = refresh_expire or 24
        return _app

    return _create


@pytest.fixture
def fake_client_app(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app()

    async def _engine_fake_get(*_args):
        return _fake

    async def _engine_fake_save(*_args):
        pass

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)
    monkeypatch.setattr("app.dependencies.engine.save", _engine_fake_save)

    return _fake


@pytest.fixture
def fake_refresh_client_app(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app(refresh=True)

    async def _engine_fake_get(*_args):
        return _fake

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)

    return _fake


@pytest.fixture
def fake_client_app_out_of_quota(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app(quota=0, owner="owner@example.com")

    async def _engine_fake_get(*_args):
        return _fake

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)

    return _fake


@pytest.fixture
def fake_client_app_use_quota(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app()

    async def _engine_fake_get(*_args):
        return _fake

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)

    return _fake


@pytest.fixture
def fake_client_app_low_quota(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app(quota=5)

    async def _engine_fake_get(*_args):
        return _fake

    async def _engine_fake_save(*_args):
        pass

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)
    monkeypatch.setattr("app.dependencies.engine.save", _engine_fake_save)

    return _fake


@pytest.fixture
def fake_client_app_low_quota_notified_today(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app(
        quota=5, low_quota_last_notified=datetime.datetime.today()
    )

    async def _engine_fake_get(*_args):
        return _fake

    async def _engine_fake_save(*_args):
        pass

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)
    monkeypatch.setattr("app.dependencies.engine.save", _engine_fake_save)

    return _fake


@pytest.fixture
def fake_client_app_low_quota_notified_yesterday(create_fake_client_app, monkeypatch):
    yesterday = datetime.datetime.today() - datetime.timedelta(days=1, hours=1)
    _fake = create_fake_client_app(quota=5, low_quota_last_notified=yesterday)

    async def _engine_fake_get(*_args):
        return _fake

    async def _engine_fake_save(*_args):
        pass

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)
    monkeypatch.setattr("app.dependencies.engine.save", _engine_fake_save)

    return _fake


@pytest.fixture
def fake_client_app_low_quota_custom_threshold(create_fake_client_app, monkeypatch):
    _fake = create_fake_client_app(quota=98, low_quota_threshold=100)

    async def _engine_fake_get(*_args):
        return _fake

    async def _engine_fake_save(*_args):
        pass

    monkeypatch.setattr("app.dependencies.engine.find_one", _engine_fake_get)
    monkeypatch.setattr("app.dependencies.engine.save", _engine_fake_save)

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
    return PWD_CONTEXT
