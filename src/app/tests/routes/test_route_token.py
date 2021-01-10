from unittest.mock import AsyncMock

import ujson

from app.security.token import TokenVerificationError


def test_verify_token(mocker, test_client, fake_client_app):
    fake_headers = {"fake": "headers"}
    fake_claims = {"fake": "claims"}
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify",
        return_value=(fake_headers, fake_claims),
    )

    response = test_client.get(
        f"/token/verify/{fake_client_app.app_id}", json={"idToken": "fake_token"}
    )

    assert response.status_code == 200
    assert response.json()["headers"] == fake_headers
    assert response.json()["claims"] == fake_claims

    verify_mock.assert_called_once_with("fake_token", fake_client_app)


def test_verify_token_fails(monkeypatch, test_client, fake_client_app):
    def _fail_token(*args):
        raise TokenVerificationError

    monkeypatch.setattr("app.routes.token.security_token.verify", _fail_token)

    response = test_client.get(
        f"/token/verify/{fake_client_app.app_id}", json={"idToken": "fake_token"}
    )

    assert response.status_code == 401
    assert response.json().get("headers") is None
    assert response.json().get("claims") is None


def test_verify_token_not_found(app_not_found, test_client, mocker):
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify",
    )

    response = test_client.get(f"/token/verify/12345", json={"idToken": "fake_token"})

    assert response.status_code == 404
    assert response.json().get("headers") is None
    assert response.json().get("claims") is None

    verify_mock.assert_not_called()


def test_refresh_success(fake_refresh_client_app, test_client, mocker):
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify_refresh_token",
        return_value="fake_id_token",
        new_callable=AsyncMock,
    )

    response = test_client.get(
        f"/token/refresh/{fake_refresh_client_app.app_id}",
        json={"refreshToken": "test12345"},
    )

    assert response.status_code == 200
    assert response.json().get("idToken") == "fake_id_token"
    assert response.json().get("refreshToken") == "test12345"

    verify_mock.assert_called_once_with("test12345", fake_refresh_client_app)


def test_refresh_not_found(app_not_found, mocker, test_client):
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify_refresh_token",
        new_callable=AsyncMock,
    )

    response = test_client.get(
        f"/token/refresh/12345",
        json={"refreshToken": "test12345"},
    )

    assert response.status_code == 404
    assert response.json().get("idToken") is None
    assert response.json().get("refreshToken") is None

    verify_mock.assert_not_called()


def test_refresh_no_refresh_key(fake_client_app, mocker, test_client):
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify_refresh_token",
        new_callable=AsyncMock,
    )

    response = test_client.get(
        f"/token/refresh/{fake_client_app.app_id}",
        json={"refreshToken": "test12345"},
    )

    assert response.status_code == 403
    assert response.json().get("idToken") is None
    assert response.json().get("refreshToken") is None

    verify_mock.assert_not_called()


def test_refresh_verify_failed(fake_refresh_client_app, mocker, test_client):
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify_refresh_token",
        new_callable=AsyncMock,
        side_effect=TokenVerificationError(),
    )

    response = test_client.get(
        f"/token/refresh/{fake_refresh_client_app.app_id}",
        json={"refreshToken": "test12345"},
    )

    assert response.status_code == 401
    assert response.json().get("idToken") is None
    assert response.json().get("refreshToken") is None

    verify_mock.assert_called_once_with("test12345", fake_refresh_client_app)
