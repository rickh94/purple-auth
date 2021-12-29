from unittest.mock import AsyncMock

import pytest

from app.io import email as io_email


@pytest.fixture
def mock_token_generate(mocker):
    return mocker.patch(
        "app.routes.otp.security_token.generate", return_value="fake_token"
    )


@pytest.fixture
def mock_otp_verify_success(mocker):
    return mocker.patch(
        "app.routes.otp.security_otp.verify",
        return_value=True,
    )


@pytest.fixture
def mock_otp_verify_failure(mocker):
    return mocker.patch(
        "app.routes.otp.security_otp.verify",
        return_value=False,
    )


@pytest.fixture
def fake_code():
    return "11111111"


def test_request_otp(monkeypatch, mocker, test_client, fake_client_app, fake_email):
    mock_send_email = mocker.patch("app.routes.otp.io_email.send")
    mock_otp_generate = mocker.patch(
        "app.routes.otp.security_otp.generate", return_value="11111111"
    )

    response = test_client.post(
        f"/otp/request/{fake_client_app.app_id}", json={"email": fake_email}
    )

    assert response.status_code == 200
    mock_send_email.assert_called_once_with(
        to=fake_email,
        subject="Your One Time Login Code",
        text=f"Your code is 11111111. It will expire in 5 minutes.",
        from_name=fake_client_app.name,
    )
    mock_otp_generate.assert_called_once_with(fake_email, fake_client_app.app_id)


def test_request_otp_no_app(app_not_found, mocker, test_client, fake_email):
    mock_send_email = mocker.patch("app.routes.otp.io_email.send")
    mock_otp_generate = mocker.patch("app.routes.otp.security_otp.generate")

    response = test_client.post(f"/otp/request/12345", json={"email": fake_email})

    assert response.status_code == 404
    mock_send_email.assert_not_called()
    mock_otp_generate.assert_not_called()


def test_request_otp_email_failed(
    monkeypatch, test_client, fake_email, fake_client_app
):
    async def _fail_to_email(*_args, **_kwargs):
        raise io_email.EmailError

    monkeypatch.setattr("app.routes.otp.io_email.send", _fail_to_email)
    monkeypatch.setattr(
        "app.routes.otp.security_otp.generate", lambda *args: "11111111"
    )

    response = test_client.post(
        f"/otp/request/{fake_client_app.app_id}",
        json={"email": fake_email},
    )

    assert response.status_code == 500


def test_request_otp_fails_out_of_quota(
    mocker, test_client, fake_email, fake_client_app_out_of_quota
):
    mock_send_email = mocker.patch("app.dependencies.io_email.send")

    response = test_client.post(
        f"/otp/request/{fake_client_app_out_of_quota.app_id}",
        json={"email": fake_email},
    )

    assert response.status_code == 503
    assert (
        response.json()["detail"]
        == "This app does not have any authentications remaining. Please contact "
        "your administrator"
    )

    mock_send_email.assert_called_once_with(
        to=fake_client_app_out_of_quota.owner,
        subject=f"{fake_client_app_out_of_quota.name} is out of Authentications",
        text=f"{fake_client_app_out_of_quota.name} has reached its quota of "
        f"authentications. No further authentications will be processed. "
        f"Please reply to this email to purchase more.\nRick Henry\nRick Henry "
        f"Development\nhttps://rickhenry.dev",
        from_name="Rick Henry",
        reply_to="rickhenry@rickhenry.dev",
    )


def test_request_otp_uses_quota(
    mocker, test_client, fake_email, fake_client_app_use_quota
):
    _mock_send_email = mocker.patch("app.routes.otp.io_email.send")
    _mock_otp_generate = mocker.patch(
        "app.routes.otp.security_otp.generate", return_value="11111111"
    )
    mock_save = mocker.patch("app.dependencies.engine.save")
    prev_quota = fake_client_app_use_quota.quota

    response = test_client.post(
        f"/otp/request/{fake_client_app_use_quota.app_id}",
        json={"email": fake_email},
    )

    assert response.status_code == 200
    assert fake_client_app_use_quota.quota == prev_quota - 1

    mock_save.assert_called_once_with(fake_client_app_use_quota)


def test_request_otp_notifies_low_quota(
    mocker, test_client, fake_email, fake_client_app_low_quota
):
    mock_send_email = mocker.patch("app.dependencies.io_email.send")
    _mock_otp_generate = mocker.patch(
        "app.routes.otp.security_otp.generate", return_value="11111111"
    )

    response = test_client.post(
        f"/otp/request/{fake_client_app_low_quota.app_id}",
        json={"email": fake_email},
    )

    assert response.status_code == 200

    assert mock_send_email.call_count == 2
    mock_send_email.assert_any_call(
        to=fake_client_app_low_quota.owner,
        subject=f"{fake_client_app_low_quota.name} is almost out of Authentications",
        text=f"{fake_client_app_low_quota.name} has almost reached its quota of "
        f"authentications. It will process {fake_client_app_low_quota.quota} more "
        f"authentications before it stops authenticating users. "
        f"Please reply to this email to purchase more.\nRick Henry\nRick Henry "
        f"Development\nhttps://rickhenry.dev",
        from_name="Rick Henry",
        reply_to="rickhenry@rickhenry.dev",
    )


def test_request_otp_notifies_low_quota_only_once_per_day(
    mocker, test_client, fake_email, fake_client_app_low_quota_notified_today
):
    fca = fake_client_app_low_quota_notified_today
    mock_send_email = mocker.patch("app.dependencies.io_email.send")
    _mock_otp_generate = mocker.patch(
        "app.routes.otp.security_otp.generate", return_value="11111111"
    )

    response = test_client.post(
        f"/otp/request/{fca.app_id}",
        json={"email": fake_email},
    )

    assert response.status_code == 200

    assert mock_send_email.call_count == 1


def test_request_otp_notifies_low_quota_next_day(
    mocker, test_client, fake_email, fake_client_app_low_quota_notified_yesterday
):
    fca = fake_client_app_low_quota_notified_yesterday
    mock_send_email = mocker.patch("app.dependencies.io_email.send")
    _mock_otp_generate = mocker.patch(
        "app.routes.otp.security_otp.generate", return_value="11111111"
    )

    response = test_client.post(
        f"/otp/request/{fca.app_id}",
        json={"email": fake_email},
    )

    assert response.status_code == 200

    assert mock_send_email.call_count == 2
    mock_send_email.assert_any_call(
        to=fca.owner,
        subject=f"{fca.name} is almost out of Authentications",
        text=f"{fca.name} has almost reached its quota of "
        f"authentications. It will process {fca.quota} more "
        f"authentications before it stops authenticating users. "
        f"Please reply to this email to purchase more.\nRick Henry\nRick Henry "
        f"Development\nhttps://rickhenry.dev",
        from_name="Rick Henry",
        reply_to="rickhenry@rickhenry.dev",
    )


def test_request_otp_notifies_low_quota_custom_threshold(
    mocker, test_client, fake_email, fake_client_app_low_quota_custom_threshold
):
    fca = fake_client_app_low_quota_custom_threshold
    mock_send_email = mocker.patch("app.dependencies.io_email.send")
    _mock_otp_generate = mocker.patch(
        "app.routes.otp.security_otp.generate", return_value="11111111"
    )

    response = test_client.post(
        f"/otp/request/{fca.app_id}",
        json={"email": fake_email},
    )

    assert response.status_code == 200

    assert mock_send_email.call_count == 2
    mock_send_email.assert_any_call(
        to=fca.owner,
        subject=f"{fca.name} is almost out of Authentications",
        text=f"{fca.name} has almost reached its quota of "
        f"authentications. It will process {fca.quota} more "
        f"authentications before it stops authenticating users. "
        f"Please reply to this email to purchase more.\nRick Henry\nRick Henry "
        f"Development\nhttps://rickhenry.dev",
        from_name="Rick Henry",
        reply_to="rickhenry@rickhenry.dev",
    )


def test_confirm_otp(
    fake_client_app,
    fake_email,
    test_client,
    mock_token_generate,
    mock_otp_verify_success,
    fake_code,
):
    response = test_client.post(
        f"/otp/confirm/{fake_client_app.app_id}",
        json={"email": fake_email, "code": fake_code},
    )

    assert response.status_code == 200
    assert response.json()["idToken"] == "fake_token"
    assert response.json().get("refreshToken") is None

    mock_otp_verify_success.assert_called_once_with(
        fake_email, fake_code, fake_client_app.app_id
    )
    mock_token_generate.assert_called_once_with(fake_email, fake_client_app)


def test_confirm_otp_fails(
    fake_client_app,
    test_client,
    mock_token_generate,
    mock_otp_verify_failure,
    fake_email,
    fake_code,
):
    response = test_client.post(
        f"/otp/confirm/{fake_client_app.app_id}",
        json={"email": fake_email, "code": fake_code},
    )

    assert response.status_code == 401

    mock_otp_verify_failure.assert_called_once_with(
        fake_email, fake_code, fake_client_app.app_id
    )
    mock_token_generate.assert_not_called()


def test_confirm_otp_not_found(
    test_client,
    app_not_found,
    mock_token_generate,
    mock_otp_verify_success,
    fake_email,
    fake_code,
):
    response = test_client.post(
        f"/otp/confirm/12345",
        json={"email": fake_email, "code": fake_code},
    )

    assert response.status_code == 404

    mock_otp_verify_success.assert_not_called()
    mock_token_generate.assert_not_called()


def test_confirm_otp_with_refresh(
    mocker,
    test_client,
    fake_refresh_client_app,
    fake_email,
    mock_token_generate,
    mock_otp_verify_success,
    fake_code,
):
    mock_refresh_token_generate = mocker.patch(
        "app.routes.otp.security_token.generate_refresh_token",
        new_callable=AsyncMock,
        return_value="fake_refresh_token",
    )

    response = test_client.post(
        f"/otp/confirm/{fake_refresh_client_app.app_id}",
        json={"email": fake_email, "code": fake_code},
    )

    assert response.status_code == 200
    assert response.json()["idToken"] == "fake_token"
    assert response.json()["refreshToken"] == "fake_refresh_token"

    mock_otp_verify_success.assert_called_once_with(
        fake_email, fake_code, fake_refresh_client_app.app_id
    )
    mock_token_generate.assert_called_once_with(fake_email, fake_refresh_client_app)
    mock_refresh_token_generate.assert_called_once_with(
        fake_email, fake_refresh_client_app
    )
