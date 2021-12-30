import secrets
from urllib.parse import quote_plus

import pytest

from app import config
from app.io import email as io_email


@pytest.fixture
def mock_token_generate(mocker):
    return mocker.patch(
        "app.routes.magic.security_token.generate", return_value="fake_token"
    )


@pytest.fixture
def mock_magic_verify_success(mocker, fake_email):
    return mocker.patch(
        "app.routes.magic.security_magic.verify", return_value=fake_email
    )


@pytest.fixture
def mock_magic_verify_failure(mocker):
    return mocker.patch("app.routes.magic.security_magic.verify", return_value=None)


@pytest.fixture
def fake_secret():
    return secrets.token_urlsafe()


@pytest.fixture
def fake_enc_email(fake_email):
    return config.FERNET.encrypt(fake_email.encode("utf-8"))


def test_request_magic(mocker, test_client, fake_client_app, fake_email):
    fake_link = "http://auth.example.com/test123?secret=12345"
    mock_send_email = mocker.patch("app.routes.magic.io_email.send")
    mock_magic_generate = mocker.patch(
        "app.routes.magic.security_magic.generate",
        return_value=fake_link,
    )

    response = test_client.post(
        f"/magic/request/{fake_client_app.app_id}", json={"email": fake_email}
    )

    assert response.status_code == 200

    mock_send_email.assert_called_once_with(
        to=fake_email,
        subject="Your Magic Sign In Link",
        text=f"Click or copy this link to sign in: {fake_link}. It will expire "
        f"in {config.MAGIC_LIFETIME} minutes.",
        from_name=fake_client_app.name,
    )
    mock_magic_generate.assert_called_once_with(fake_email, fake_client_app.app_id)


def test_request_magic_uses_quota(
    mocker, test_client, fake_client_app_use_quota, fake_email
):
    fca = fake_client_app_use_quota
    fake_link = "http://auth.example.com/test123?secret=12345"
    _mock_send_email = mocker.patch("app.routes.magic.io_email.send")
    _mock_magic_generate = mocker.patch(
        "app.routes.magic.security_magic.generate",
        return_value=fake_link,
    )
    prev_quota = fca.quota

    response = test_client.post(
        f"/magic/request/{fca.app_id}", json={"email": fake_email}
    )

    assert response.status_code == 200
    assert fca.quota == prev_quota - 1

    fca.save.assert_called()


def test_request_magic_fails_out_of_quota(
    mocker, test_client, fake_client_app_out_of_quota, fake_email
):
    fca = fake_client_app_out_of_quota
    fake_link = "http://auth.example.com/test123?secret=12345"
    mock_send_email = mocker.patch("app.dependencies.io_email.send")
    _mock_magic_generate = mocker.patch(
        "app.routes.magic.security_magic.generate",
        return_value=fake_link,
    )

    response = test_client.post(
        f"/magic/request/{fca.app_id}", json={"email": fake_email}
    )

    assert response.status_code == 503

    mock_send_email.assert_called_once_with(
        to=fake_client_app_out_of_quota.owner,
        subject=f"{fca.name} is out of Authentications",
        text=f"{fca.name} has reached its quota of "
        f"authentications. No further authentications will be processed. "
        f"Please reply to this email to purchase more.\nRick Henry\nRick Henry "
        f"Development\nhttps://rickhenry.dev",
        from_name="Rick Henry",
        reply_to="rickhenry@rickhenry.dev",
    )


def test_request_magic_notifies_low_quota(
    mocker, test_client, fake_client_app_low_quota, fake_email
):
    fca = fake_client_app_low_quota
    fake_link = "http://auth.example.com/test123?secret=12345"
    mock_send_email = mocker.patch("app.routes.magic.io_email.send")
    _mock_magic_generate = mocker.patch(
        "app.routes.magic.security_magic.generate",
        return_value=fake_link,
    )

    response = test_client.post(
        f"/magic/request/{fca.app_id}", json={"email": fake_email}
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


def test_request_magic_notifies_low_quota_once_per_day(
    mocker, test_client, fake_client_app_low_quota_notified_today, fake_email
):
    fca = fake_client_app_low_quota_notified_today
    fake_link = "http://auth.example.com/test123?secret=12345"
    mock_send_email = mocker.patch("app.routes.magic.io_email.send")
    _mock_magic_generate = mocker.patch(
        "app.routes.magic.security_magic.generate",
        return_value=fake_link,
    )

    response = test_client.post(
        f"/magic/request/{fca.app_id}", json={"email": fake_email}
    )

    assert response.status_code == 200
    assert mock_send_email.call_count == 1


def test_request_magic_notifies_low_quota_next_day(
    mocker, test_client, fake_client_app_low_quota_notified_yesterday, fake_email
):
    fca = fake_client_app_low_quota_notified_yesterday
    fake_link = "http://auth.example.com/test123?secret=12345"
    mock_send_email = mocker.patch("app.routes.magic.io_email.send")
    _mock_magic_generate = mocker.patch(
        "app.routes.magic.security_magic.generate",
        return_value=fake_link,
    )

    response = test_client.post(
        f"/magic/request/{fca.app_id}", json={"email": fake_email}
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


def test_request_magic_notifies_low_quota_custom_threshold(
    mocker, test_client, fake_client_app_low_quota_custom_threshold, fake_email
):
    fca = fake_client_app_low_quota_custom_threshold
    fake_link = "http://auth.example.com/test123?secret=12345"
    mock_send_email = mocker.patch("app.routes.magic.io_email.send")
    _mock_magic_generate = mocker.patch(
        "app.routes.magic.security_magic.generate",
        return_value=fake_link,
    )

    response = test_client.post(
        f"/magic/request/{fca.app_id}", json={"email": fake_email}
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


def test_request_magic_no_app(app_not_found, mocker, test_client, fake_email):
    mock_send_email = mocker.patch("app.routes.otp.io_email.send")
    mock_otp_generate = mocker.patch("app.routes.otp.security_otp.generate")

    response = test_client.post(f"/magic/request/12345", json={"email": fake_email})

    assert response.status_code == 404
    mock_send_email.assert_not_called()
    mock_otp_generate.assert_not_called()


def test_request_magic_email_failed(
    monkeypatch, test_client, fake_email, fake_client_app
):
    async def _fail_to_email(*_args, **_kwargs):
        raise io_email.EmailError

    monkeypatch.setattr("app.routes.magic.io_email.send", _fail_to_email)
    monkeypatch.setattr(
        "app.routes.magic.security_magic.generate",
        lambda *args: "http://auth.example.com/test",
    )

    response = test_client.post(
        f"/magic/request/{fake_client_app.app_id}", json={"email": fake_email}
    )

    assert response.status_code == 500


def test_confirm_magic(
    fake_client_app,
    fake_email,
    mock_magic_verify_success,
    test_client,
    fake_secret,
    fake_enc_email,
    mock_token_generate,
):
    response = test_client.request(
        "GET",
        f"/magic/confirm/{fake_client_app.app_id}",
        params={"secret": fake_secret, "id": fake_enc_email},
    )

    assert response.status_code == 307

    assert "location" in response.headers
    host, query = response.headers["location"].split("?")
    assert host == fake_client_app.redirect_url

    key, value = query.split("=")
    assert key == "idToken"
    assert value == "fake_token"

    mock_magic_verify_success.assert_called_once_with(
        fake_enc_email.decode("utf-8"), fake_secret, fake_client_app.app_id
    )
    mock_token_generate.assert_called_once_with(fake_email, fake_client_app)


def test_confirm_magic_with_refresh(
    fake_refresh_client_app,
    fake_email,
    mock_magic_verify_success,
    test_client,
    fake_secret,
    fake_enc_email,
    mock_token_generate,
    mocker,
):
    mock_refresh_token_generate = mocker.patch(
        "app.routes.magic.security_token.generate_refresh_token",
        return_value="fake_refresh_token",
    )
    response = test_client.request(
        "GET",
        f"/magic/confirm/{fake_refresh_client_app.app_id}",
        params={"id": fake_enc_email, "secret": fake_secret},
    )

    assert response.status_code == 307
    assert "location" in response.headers

    host, query = response.headers["location"].split("?")
    assert host == fake_refresh_client_app.redirect_url
    id_token_q, refresh_token_q = query.split("&")
    id_token_key, id_token_value = id_token_q.split("=")
    refresh_token_key, refresh_token_value = refresh_token_q.split("=")

    assert id_token_key == "idToken"
    assert id_token_value == "fake_token"
    assert refresh_token_key == "refreshToken"
    assert refresh_token_value == "fake_refresh_token"

    mock_magic_verify_success.assert_called_once_with(
        fake_enc_email.decode("utf-8"), fake_secret, fake_refresh_client_app.app_id
    )
    mock_token_generate.assert_called_once_with(fake_email, fake_refresh_client_app)
    mock_refresh_token_generate.assert_called_once_with(
        fake_email, fake_refresh_client_app
    )


def test_confirm_magic_fails_with_error_url(
    create_fake_client_app,
    fake_enc_email,
    mock_magic_verify_failure,
    test_client,
    mock_token_generate,
    monkeypatch,
    fake_secret,
    create_fake_queryset,
):
    error_url = "https://example.com/auth-failure"
    fake_client_app_error_url = create_fake_client_app(failure_redirect_url=error_url)

    def _fake_query(*_args):
        return create_fake_queryset(get_return=fake_client_app_error_url)

    monkeypatch.setattr("app.dependencies.ClientApp.query", _fake_query)
    response = test_client.get(
        f"/magic/confirm/{fake_client_app_error_url.app_id}?secret={fake_secret}"
        f"&id={quote_plus(fake_enc_email)}"
    )

    assert response.url == error_url
    mock_magic_verify_failure.assert_called_once_with(
        fake_enc_email.decode("utf-8"), fake_secret, fake_client_app_error_url.app_id
    )
    mock_token_generate.assert_not_called()


def test_confirm_magic_fails_no_error_url(
    fake_client_app,
    fake_enc_email,
    mock_magic_verify_failure,
    test_client,
    mock_token_generate,
    fake_secret,
):
    response = test_client.get(
        f"/magic/confirm/{fake_client_app.app_id}?secret={fake_secret}"
        f"&id={quote_plus(fake_enc_email)}"
    )

    assert response.status_code == 401

    mock_magic_verify_failure.assert_called_once_with(
        fake_enc_email.decode("utf-8"), fake_secret, fake_client_app.app_id
    )
    mock_token_generate.assert_not_called()


def test_confirm_magic_not_found(
    app_not_found,
    fake_enc_email,
    test_client,
    mock_token_generate,
    fake_secret,
    mock_magic_verify_success,
):
    response = test_client.get(
        f"/magic/confirm/123456?secret={fake_secret}"
        f"&id={quote_plus(fake_enc_email)}"
    )
    assert response.status_code == 404

    mock_token_generate.assert_not_called()
    mock_magic_verify_success.assert_not_called()
