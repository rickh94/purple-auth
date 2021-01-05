from app.io import email as io_email


def test_request_otp(mocker, test_client, fake_client_app, faker):
    mocked_send_email = mocker.patch("app.routes.otp.io_email.send")
    mock_otp_generate = mocker.patch(
        "app.routes.otp.security_otp.generate", return_value="11111111"
    )
    test_email = faker.email()

    response = test_client.post(
        f"/otp/request/{fake_client_app.app_id}", json={"email": test_email}
    )

    assert response.status_code == 200
    mocked_send_email.assert_called_once_with(
        to=test_email,
        subject="Your One Time Login Code",
        text=f"Your code is 11111111. It will expire in 5 minutes.",
        from_name=fake_client_app.name,
    )
    mock_otp_generate.assert_called_once_with(test_email, fake_client_app.app_id)


def test_request_otp_no_app(app_not_found, mocker, test_client, faker):
    mock_send_email = mocker.patch("app.routes.otp.io_email.send")
    mock_otp_generate = mocker.patch("app.routes.otp.security_otp.generate")

    response = test_client.post(f"/otp/request/12345", json={"email": faker.email()})

    assert response.status_code == 404
    mock_send_email.assert_not_called()
    mock_otp_generate.assert_not_called()


def test_request_otp_email_failed(monkeypatch, test_client, faker, fake_client_app):
    async def _fail_to_email(*_args, **_kwargs):
        raise io_email.EmailError

    monkeypatch.setattr("app.routes.otp.io_email.send", _fail_to_email)
    monkeypatch.setattr(
        "app.routes.otp.security_otp.generate", lambda *args: "11111111"
    )
    test_email = faker.email()

    response = test_client.post(
        f"/otp/request/{fake_client_app.app_id}",
        json={"email": test_email},
    )

    assert response.status_code == 500


def test_confirm_otp(fake_client_app, mocker, faker, test_client):
    mock_otp_verify = mocker.patch(
        "app.routes.otp.security_otp.verify",
        return_value=True,
    )
    mock_token_generate = mocker.patch(
        "app.routes.otp.security_token.generate", return_value="fake_token"
    )
    test_email = faker.email()
    fake_code = "11111111"

    response = test_client.post(
        f"/otp/confirm/{fake_client_app.app_id}",
        json={"email": test_email, "code": fake_code},
    )

    assert response.status_code == 200
    assert response.json()["idToken"] == "fake_token"

    mock_otp_verify.assert_called_once_with(
        test_email, fake_code, fake_client_app.app_id
    )
    mock_token_generate.assert_called_once_with(test_email, fake_client_app)


def test_confirm_otp_fails(fake_client_app, monkeypatch, mocker, faker, test_client):
    mock_otp_verify = mocker.patch(
        "app.routes.otp.security_otp.verify",
        return_value=False,
    )
    mock_token_generate = mocker.patch("app.routes.otp.security_token.generate")
    test_email = faker.email()
    fake_code = "11111111"

    response = test_client.post(
        f"/otp/confirm/{fake_client_app.app_id}",
        json={"email": test_email, "code": fake_code},
    )

    assert response.status_code == 401

    mock_otp_verify.assert_called_once_with(
        test_email, fake_code, fake_client_app.app_id
    )
    mock_token_generate.assert_not_called()


def test_confirm_otp_not_found(mocker, faker, test_client, app_not_found):
    mock_otp_verify = mocker.patch(
        "app.routes.otp.security_otp.verify",
    )
    mock_token_generate = mocker.patch("app.routes.otp.security_token.generate")
    test_email = faker.email()
    fake_code = "11111111"

    response = test_client.post(
        f"/otp/confirm/12345",
        json={"email": test_email, "code": fake_code},
    )

    assert response.status_code == 404

    mock_otp_verify.assert_not_called()
    mock_token_generate.assert_not_called()
