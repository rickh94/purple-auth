import os
import uuid

import pytest
from jwcrypto import jwk

from app.models.client_app_model import ClientApp
from app.portal.models.user_model import User
from app.portal.security import oauth2_scheme


@pytest.fixture
def user1(faker):
    return User(
        email=faker.email(),
        name=faker.name(),
    )


@pytest.fixture
def user2(faker):
    return User(
        email=faker.email(),
        name=faker.name(),
    )


@pytest.fixture
def deletable_user(faker):
    return User(
        email=faker.email(),
        name=faker.name(),
        deletion_protection=False,
    )


@pytest.fixture
def superuser():
    return User(email=os.getenv("WEBMASTER_EMAIL"))


@pytest.fixture
@pytest.mark.asyncio
async def user1_app1(user1, faker, monkeypatch):
    app = ClientApp(
        name=faker.company(),
        app_id=str(uuid.uuid4()),
        refresh_token_expire_hours=None,
        redirect_url="https://example.com/magic",
        failure_redirect_url="https://example.com/failed",
        owner=user1.email,
        quota=500,
        low_quota_threshold=10,
        unlimited=False,
    )
    key = jwk.JWK.generate(kty="EC", size=2048)
    app.set_key(key)
    app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
    app.refresh_token_expire_hours = 24
    await app.insert()
    return app


@pytest.fixture
@pytest.mark.asyncio
async def deletable_user_app1(deletable_user, faker, monkeypatch):
    app = ClientApp(
        name=faker.company(),
        app_id=str(uuid.uuid4()),
        refresh_token_expire_hours=None,
        redirect_url="https://example.com/magic",
        failure_redirect_url="https://example.com/failed",
        owner=deletable_user.email,
        quota=500,
        low_quota_threshold=10,
        unlimited=False,
    )
    key = jwk.JWK.generate(kty="EC", size=2048)
    app.set_key(key)
    app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
    app.refresh_token_expire_hours = 24
    await app.insert()
    return app


@pytest.fixture
@pytest.mark.asyncio
async def deletable_user_app2(deletable_user, faker, monkeypatch):
    app = ClientApp(
        name=faker.company(),
        app_id=str(uuid.uuid4()),
        refresh_token_expire_hours=None,
        redirect_url="https://example.com/magic",
        failure_redirect_url="https://example.com/failed",
        owner=deletable_user.email,
        quota=500,
        low_quota_threshold=10,
        unlimited=False,
    )
    key = jwk.JWK.generate(kty="EC", size=2048)
    app.set_key(key)
    app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
    app.refresh_token_expire_hours = 24
    await app.insert()
    return app


@pytest.fixture
@pytest.mark.asyncio
async def user1_app2(user1, faker, monkeypatch):
    app = ClientApp(
        name=faker.company(),
        app_id=str(uuid.uuid4()),
        refresh_token_expire_hours=None,
        redirect_url="https://example.com/magic",
        failure_redirect_url="https://example.com/failed",
        owner=user1.email,
        quota=500,
        low_quota_threshold=10,
        unlimited=False,
    )
    key = jwk.JWK.generate(kty="EC", size=2048)
    app.set_key(key)
    app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
    app.refresh_token_expire_hours = 24
    await app.insert()
    return app


@pytest.fixture
@pytest.mark.asyncio
async def user1_app3(user1, faker, monkeypatch):
    app = ClientApp(
        name=faker.company(),
        app_id=str(uuid.uuid4()),
        refresh_token_expire_hours=None,
        redirect_url="https://example.com/magic",
        failure_redirect_url="https://example.com/failed",
        owner=user1.email,
        quota=500,
        low_quota_threshold=10,
        unlimited=False,
    )
    key = jwk.JWK.generate(kty="EC", size=2048)
    app.set_key(key)
    app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
    app.refresh_token_expire_hours = 24
    await app.insert()
    return app


@pytest.fixture
@pytest.mark.asyncio
async def user1_app_no_refresh(user1, faker, monkeypatch):
    app = ClientApp(
        name=faker.company(),
        app_id=str(uuid.uuid4()),
        refresh_token_expire_hours=None,
        redirect_url="https://example.com/magic",
        failure_redirect_url="https://example.com/failed",
        owner=user1.email,
        quota=500,
        low_quota_threshold=10,
        unlimited=False,
    )
    key = jwk.JWK.generate(kty="EC", size=2048)
    app.set_key(key)
    await app.insert()
    return app


@pytest.fixture
@pytest.mark.asyncio
async def user1_app_unprotected(user1, faker, monkeypatch):
    app = ClientApp(
        name=faker.company(),
        app_id=str(uuid.uuid4()),
        refresh_token_expire_hours=None,
        redirect_url="https://example.com/magic",
        failure_redirect_url="https://example.com/failed",
        owner=user1.email,
        quota=500,
        low_quota_threshold=10,
        unlimited=False,
    )

    key = jwk.JWK.generate(kty="EC", size=2048)
    app.set_key(key)
    app.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
    app.refresh_token_expire_hours = 24
    app.deletion_protection = False

    await app.insert()
    return app


@pytest.fixture
def user1_client(user1, test_client, monkeypatch):
    async def fake_verify_token(*_args):
        return {
            "headers": {"alg": "ES256", "typ": "JWT"},
            "claims": {
                "iss": os.getenv("HOST"),
                "sub": user1.email,
            },
        }

    monkeypatch.setattr("app.portal.security.auth_client.verify", fake_verify_token)

    return test_client


@pytest.fixture
def user2_client(user2, test_client, monkeypatch):
    async def fake_verify_token(*_args):
        return {
            "headers": {"alg": "ES256", "typ": "JWT"},
            "claims": {
                "iss": os.getenv("HOST"),
                "sub": user2.email,
            },
        }

    monkeypatch.setattr("app.portal.security.auth_client.verify", fake_verify_token)

    return test_client


@pytest.fixture
def superuser_client(superuser, test_client, monkeypatch):
    async def fake_verify_token(*_args):
        return {
            "headers": {"alg": "ES256", "typ": "JWT"},
            "claims": {
                "iss": os.getenv("HOST"),
                "sub": superuser.email,
            },
        }

    monkeypatch.setattr("app.portal.security.auth_client.verify", fake_verify_token)

    return test_client


@pytest.fixture
def deletable_user_client(deletable_user, test_client, monkeypatch):
    async def fake_verify_token(*_args):
        return {
            "headers": {"alg": "ES256", "typ": "JWT"},
            "claims": {
                "iss": os.getenv("HOST"),
                "sub": deletable_user.email,
            },
        }

    monkeypatch.setattr("app.portal.security.auth_client.verify", fake_verify_token)

    return test_client


@pytest.fixture
def fake_cookies():
    return {
        oauth2_scheme.token_name: "fake_token",
        oauth2_scheme.refresh_token_name: "fake_refresh_token",
    }
