import datetime
import uuid

import jwcrypto.jwk as jwk
import mongox
import pytest
from faker import Faker
from fastapi.testclient import TestClient

from app.models.client_app_model import ClientApp
from app.main import app
from app.security.context import PWD_CONTEXT


@pytest.fixture(autouse=True)
def random_seed(faker):
    """Set faker to a random seed so it won't use the same data for every test."""
    faker.random.seed()


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def create_fake_client_app(faker, mocker):
    def _create(
        app_id=None,
        refresh=False,
        refresh_expire=None,
        failure_redirect_url=None,
        owner=None,
        quota=500,
        low_quota_threshold=10,
        low_quota_last_notified=None,
        unlimited=False,
        app_name=None,
    ):
        if not app_id:
            app_id = str(uuid.uuid4())
        if not app_name:
            app_name = faker.company()
        key = jwk.JWK.generate(kty="EC", size=2048)
        mocker.patch("mongox.Model.delete")
        mocker.patch("mongox.Model.save")
        _app = ClientApp(
            name=app_name,
            app_id=app_id,
            refresh_key=None,
            refresh_token_expire_hours=None,
            key=None,
            redirect_url="http://localhost",
            failure_redirect_url=failure_redirect_url,
            owner=owner,
            quota=quota,
            low_quota_threshold=low_quota_threshold,
            unlimited=unlimited,
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
def create_fake_queryset():
    def _create(get_return=None, all_return=None, get_raises=None, all_raises=None):
        class FakeQuerySet:
            def __init__(
                self, get_return=None, all_return=None, get_raises=None, all_raises=None
            ):
                self.get_return = get_return
                self.all_return = all_return
                self.get_raises = get_raises
                self.all_raises = all_raises

            def query(self, *_args):
                return self

            async def get(self):
                if self.get_raises:
                    raise self.get_raises
                return self.get_return

            async def all(self):
                if self.all_raises:
                    raise self.all_raises
                return self.all_return

        return FakeQuerySet(
            get_return=get_return,
            all_return=all_return,
            get_raises=get_raises,
            all_raises=all_raises,
        )

    return _create


@pytest.fixture
def fake_client_app(create_fake_client_app, create_fake_queryset, monkeypatch):
    _fake = create_fake_client_app()

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def fake_refresh_client_app(create_fake_client_app, create_fake_queryset, monkeypatch):
    _fake = create_fake_client_app(refresh=True)

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def fake_client_app_out_of_quota(
    create_fake_client_app, create_fake_queryset, monkeypatch
):
    _fake = create_fake_client_app(quota=0, owner="owner@example.com")

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def fake_client_app_use_quota(
    create_fake_client_app, create_fake_queryset, monkeypatch, mocker
):
    _fake = create_fake_client_app()

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def fake_client_app_low_quota(
    create_fake_client_app, create_fake_queryset, monkeypatch
):
    _fake = create_fake_client_app(quota=5)

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def fake_client_app_low_quota_notified_today(
    create_fake_client_app, create_fake_queryset, monkeypatch
):
    _fake = create_fake_client_app(
        quota=5, low_quota_last_notified=datetime.datetime.today()
    )

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def fake_client_app_low_quota_notified_yesterday(
    create_fake_client_app, create_fake_queryset, monkeypatch
):
    yesterday = datetime.datetime.today() - datetime.timedelta(days=1, hours=1)
    _fake = create_fake_client_app(quota=5, low_quota_last_notified=yesterday)

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def fake_client_app_low_quota_custom_threshold(
    create_fake_client_app, create_fake_queryset, monkeypatch
):
    _fake = create_fake_client_app(quota=98, low_quota_threshold=100)

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def fake_client_app_unlimited(
    create_fake_client_app, create_fake_queryset, monkeypatch
):
    _fake = create_fake_client_app(quota=0, low_quota_threshold=0, unlimited=True)

    def _fake_query(*_args):
        return create_fake_queryset(get_return=_fake)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)

    return _fake


@pytest.fixture
def app_not_found(monkeypatch):
    class FakeQuerySet:
        def __init__(self):
            pass

        def query(self, *_args):
            return self

        async def get(self):
            raise mongox.NoMatchFound

    def _fake_query(*_args):
        return FakeQuerySet()

    monkeypatch.setattr("app.models.client_app_model.ClientApp.query", _fake_query)


@pytest.fixture
def fake_email():
    return Faker().email()


@pytest.fixture
def fake_app_id():
    return uuid.uuid4()


@pytest.fixture
def pwd_context():
    return PWD_CONTEXT
