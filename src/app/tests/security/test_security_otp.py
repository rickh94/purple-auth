import datetime
import secrets
import uuid
from unittest import mock

import pytest

from app import config
from app.security import otp as security_otp


@pytest.fixture
def mocked_otp_store(mocker):
    return mocker.patch("app.security.otp.OTP_STORE")


@pytest.fixture
def mocked_pwd_context(mocker):
    return mocker.patch("app.security.otp.PWD_CONTEXT")


@pytest.fixture
def fake_code():
    return "11111111"


def test_generate(monkeypatch, faker, mocked_otp_store, fake_email, fake_app_id):
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


def test_verify(
    mocked_otp_store, mocked_pwd_context, fake_email, fake_code, fake_app_id
):
    mocked_otp_store.get.return_value = "fake_hash"
    mocked_pwd_context.verify.return_value = True

    result = security_otp.verify(fake_email, fake_code, fake_app_id)

    assert result is True

    mocked_otp_store.get.assert_called_once_with(f"{fake_app_id}:otp:{fake_email}")
    mocked_pwd_context.verify.assert_called_once_with(fake_code, "fake_hash")
    mocked_otp_store.expire.assert_called_once_with(
        f"{fake_app_id}:otp:{fake_email}", datetime.timedelta(seconds=1)
    )


def test_code_expired_or_missing(mocked_otp_store, fake_email, fake_code, fake_app_id):
    mocked_otp_store.get.return_value = None

    result = security_otp.verify(fake_email, fake_code, fake_app_id)

    assert result is False

    mocked_otp_store.get.assert_called_once_with(f"{fake_app_id}:otp:{fake_email}")
    mocked_otp_store.expire.assert_not_called()


def test_verify_fails(
    mocked_otp_store, mocked_pwd_context, fake_email, fake_code, fake_app_id
):
    mocked_otp_store.get.return_value = "fake_hash"
    mocked_pwd_context.verify.return_value = False

    result = security_otp.verify(fake_email, fake_code, fake_app_id)

    assert result is False

    mocked_otp_store.get.assert_called_once_with(f"{fake_app_id}:otp:{fake_email}")
    mocked_pwd_context.verify.assert_called_once_with(fake_code, "fake_hash")
    mocked_otp_store.expire.assert_not_called()
