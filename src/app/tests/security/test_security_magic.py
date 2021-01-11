import datetime
import secrets
from unittest import mock
from urllib.parse import unquote

import pytest

from app import config
from app.security import magic as security_magic


@pytest.fixture
def mocked_magic_store(mocker):
    return mocker.patch("app.security.magic.MAGIC_STORE")


@pytest.fixture
def fake_secret():
    return secrets.token_urlsafe()


@pytest.fixture
def encrypted_email(fake_email):
    return config.FERNET.encrypt(fake_email.encode("utf-8"))


def test_generate(
    monkeypatch,
    mocked_magic_store: mock.MagicMock,
    fake_email: str,
    fake_app_id,
    fake_secret,
    mocker,
):
    monkeypatch.setattr(secrets, "token_urlsafe", lambda: fake_secret)
    returned_link = security_magic.generate(fake_email, fake_app_id)

    print(returned_link)

    main_link, encrypted_email_query = returned_link.split("&")
    assert (
        main_link == f"{config.HOST}/magic/confirm/{fake_app_id}?secret={fake_secret}"
    )
    print(main_link)
    print(encrypted_email_query)

    key, enc_email = encrypted_email_query.split("=")

    assert key == "id"

    assert config.FERNET.decrypt(
        unquote(enc_email).encode("utf-8")
    ) == fake_email.encode("utf-8")

    mocked_magic_store.set.assert_called_once_with(
        f"{fake_app_id}:magic:{fake_email}", mock.ANY
    )
    mocked_magic_store.expire.assert_called_once_with(
        f"{fake_app_id}:magic:{fake_email}",
        datetime.timedelta(minutes=config.MAGIC_LIFETIME),
    )


# noinspection DuplicatedCode
def test_verify(
    mocked_magic_store,
    pwd_context,
    encrypted_email,
    fake_email,
    fake_secret,
    fake_app_id,
):
    mocked_magic_store.get.return_value = pwd_context.hash(fake_secret)

    result = security_magic.verify(encrypted_email, fake_secret, fake_app_id)

    assert result == fake_email

    mocked_magic_store.get.assert_called_once_with(f"{fake_app_id}:magic:{fake_email}")
    mocked_magic_store.expire.assert_called_once_with(
        f"{fake_app_id}:magic:{fake_email}", datetime.timedelta(seconds=1)
    )


def test_secret_expired_or_missing(
    mocked_magic_store, encrypted_email, fake_email, fake_secret, fake_app_id
):
    mocked_magic_store.get.return_value = None

    result = security_magic.verify(encrypted_email, fake_secret, fake_app_id)

    assert result is None

    mocked_magic_store.get.assert_called_once_with(f"{fake_app_id}:magic:{fake_email}")
    mocked_magic_store.expire.asset_not_called()


def test_verify_fails(
    mocked_magic_store,
    encrypted_email,
    fake_email,
    fake_secret,
    fake_app_id,
    pwd_context,
):
    mocked_magic_store.get.return_value = pwd_context.hash("not the real secret")

    result = security_magic.verify(encrypted_email, fake_secret, fake_app_id)

    assert result is None

    mocked_magic_store.get.assert_called_once_with(f"{fake_app_id}:magic:{fake_email}")
    mocked_magic_store.expire.assert_not_called()
