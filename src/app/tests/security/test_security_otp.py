import datetime
import secrets
import uuid
from unittest import mock

import pytest
from passlib.context import CryptContext

from app import config
from app.security import otp as security_otp


@pytest.fixture
def mocked_otp_store(mocker):
    return mocker.patch("app.security.otp.OTP_STORE")


@pytest.fixture
def mocked_pwd_context(mocker):
    return mocker.patch("app.security.context.PWD_CONTEXT")


@pytest.fixture
def fake_code():
    return "11111111"


def test_generate(monkeypatch, mocked_otp_store, fake_email, fake_app_id):
    monkeypatch.setattr(secrets, "choice", lambda *args: "1")

    returned_code = security_otp.generate(fake_email, fake_app_id)

    assert returned_code == "1" * config.OTP_LENGTH

    mocked_otp_store.set.assert_called_once_with(
        f"{fake_app_id}:otp:{fake_email}", mock.ANY
    )
    mocked_otp_store.expire.assert_called_once_with(
        f"{fake_app_id}:otp:{fake_email}",
        datetime.timedelta(minutes=config.OTP_LIFETIME),
    )


# noinspection DuplicatedCode
def test_verify(mocked_otp_store, pwd_context, fake_email, fake_code, fake_app_id):
    mocked_otp_store.get.return_value = pwd_context.hash(fake_code)

    result = security_otp.verify(fake_email, fake_code, fake_app_id)

    assert result is True

    mocked_otp_store.get.assert_called_once_with(f"{fake_app_id}:otp:{fake_email}")
    mocked_otp_store.expire.assert_called_once_with(
        f"{fake_app_id}:otp:{fake_email}", datetime.timedelta(seconds=1)
    )


def test_code_expired_or_missing(mocked_otp_store, fake_email, fake_code, fake_app_id):
    mocked_otp_store.get.return_value = None

    result = security_otp.verify(fake_email, fake_code, fake_app_id)

    assert result is False

    mocked_otp_store.get.assert_called_once_with(f"{fake_app_id}:otp:{fake_email}")
    mocked_otp_store.expire.assert_not_called()


def test_verify_fails(mocked_otp_store, fake_email, fake_code, fake_app_id):
    # Argon2i raises an exception on an invalid hash. So here's a valid one for
    # a different password
    mocked_otp_store.get.return_value = (
        "$argon2id$v=19$m=65536,t=16,"
        "p=4$nPO+935P6f3/f2+NcW5NqQ$T//2mzB4P0XUa+Lx+sOu8twXinSUR+b8El7khC4Kmes"
    )

    result = security_otp.verify(fake_email, fake_code, fake_app_id)

    assert result is False

    mocked_otp_store.get.assert_called_once_with(f"{fake_app_id}:otp:{fake_email}")
    # mocked_pwd_context.verify.assert_called_once_with(fake_code, "fake_hash")
    mocked_otp_store.expire.assert_not_called()
