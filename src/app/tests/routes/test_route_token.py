from unittest.mock import AsyncMock

import pytest
import ujson

from app.security.token import TokenVerificationError


def test_verify_token(mocker, test_client, fake_client_app):
    fake_headers = {"fake": "headers"}
    fake_claims = {"fake": "claims"}
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify",
        return_value=(fake_headers, fake_claims),
    )

    response = test_client.post(
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

    response = test_client.post(
        f"/token/verify/{fake_client_app.app_id}", json={"idToken": "fake_token"}
    )

    assert response.status_code == 401
    assert response.json().get("headers") is None
    assert response.json().get("claims") is None


def test_verify_token_not_found(app_not_found, test_client, mocker):
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify",
    )

    response = test_client.post(f"/token/verify/12345", json={"idToken": "fake_token"})

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

    response = test_client.post(
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

    response = test_client.post(
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

    response = test_client.post(
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

    response = test_client.post(
        f"/token/refresh/{fake_refresh_client_app.app_id}",
        json={"refreshToken": "test12345"},
    )

    assert response.status_code == 401
    assert response.json().get("idToken") is None
    assert response.json().get("refreshToken") is None

    verify_mock.assert_called_once_with("test12345", fake_refresh_client_app)


@pytest.fixture
def delete_mock(mocker):
    return mocker.patch(
        "app.routes.token.security_token.delete_refresh_token",
        new_callable=AsyncMock,
    )


@pytest.fixture
def delete_all_mock(mocker):
    return mocker.patch(
        "app.routes.token.security_token.delete_all_refresh_tokens",
        new_callable=AsyncMock,
    )


@pytest.fixture
def fake_id_token(fake_refresh_client_app, monkeypatch, fake_email):
    def _verify_id_token(token, client_app):
        if token != "fake-token" or client_app != fake_refresh_client_app:
            raise TokenVerificationError
        return {"alg": "ES256"}, {"sub": fake_email}

    monkeypatch.setattr("app.routes.token.security_token.verify", _verify_id_token)

    return "fake-token"


def test_delete_refresh_token_success(
    test_client,
    fake_refresh_client_app,
    fake_id_token,
    delete_mock,
):
    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}/test12345",
        headers={"Authorization": f"Bearer {fake_id_token}"},
    )

    assert response.status_code == 204

    delete_mock.assert_called_once_with("test12345", fake_refresh_client_app)


def test_delete_refresh_token_no_authorization_header(
    delete_mock, test_client, fake_refresh_client_app, monkeypatch, fake_id_token
):
    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}/test12345",
    )

    assert response.status_code == 422

    delete_mock.assert_not_called()


def test_delete_refresh_token_invalid_authorization_header(
    test_client,
    fake_refresh_client_app,
    delete_mock,
):
    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}/test12345",
        headers={"Authorization": "fake-token"},
    )

    assert response.status_code == 401

    delete_mock.assert_not_called()


def test_delete_refresh_token_invalid_authorization_token(
    delete_mock, test_client, fake_id_token, fake_refresh_client_app
):
    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}/test12345",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401

    delete_mock.assert_not_called()


def test_delete_refresh_token_not_supported_in_app(
    delete_mock, test_client, fake_id_token, fake_client_app
):
    response = test_client.delete(
        f"/token/refresh/{fake_client_app.app_id}/test12345",
        headers={"Authorization": f"Bearer {fake_id_token}"},
    )

    assert response.status_code == 403

    delete_mock.assert_not_called()


def test_delete_refresh_token_invalid_refresh_token(
    test_client, fake_id_token, fake_refresh_client_app, monkeypatch
):
    def _fail_refresh_token(*args):
        raise TokenVerificationError

    monkeypatch.setattr(
        "app.routes.token.security_token.delete_refresh_token", _fail_refresh_token
    )

    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}/test12345",
        headers={"Authorization": f"Bearer {fake_id_token}"},
    )

    assert response.status_code == 401


def test_delete_refresh_token_not_found(app_not_found, test_client, delete_mock):
    response = test_client.delete(
        f"/token/refresh/12345/test12345",
        headers={"Authorization": f"Bearer fake-token"},
    )

    assert response.status_code == 404

    delete_mock.assert_not_called()


def test_delete_all_refresh_tokens_success(
    test_client,
    fake_refresh_client_app,
    fake_id_token,
    delete_all_mock,
    fake_email,
):
    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}",
        headers={"Authorization": f"Bearer {fake_id_token}"},
    )

    assert response.status_code == 204

    delete_all_mock.assert_called_once_with(fake_email, fake_refresh_client_app)


def test_delete_all_refresh_tokens_no_authorization_header(
    delete_all_mock, test_client, fake_refresh_client_app, monkeypatch, fake_id_token
):
    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}",
    )

    assert response.status_code == 422

    delete_all_mock.assert_not_called()


def test_delete_all_refresh_tokens_invalid_authorization_header(
    test_client,
    fake_refresh_client_app,
    delete_all_mock,
):
    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}",
        headers={"Authorization": "fake-token"},
    )

    assert response.status_code == 401

    delete_all_mock.assert_not_called()


def test_delete_all_refresh_tokens_invalid_authorization_token(
    delete_all_mock, test_client, fake_id_token, fake_refresh_client_app
):
    response = test_client.delete(
        f"/token/refresh/{fake_refresh_client_app.app_id}",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401

    delete_all_mock.assert_not_called()


def test_delete_all_refresh_tokens_not_supported_in_app(
    delete_all_mock, test_client, fake_id_token, fake_client_app
):
    response = test_client.delete(
        f"/token/refresh/{fake_client_app.app_id}",
        headers={"Authorization": f"Bearer {fake_id_token}"},
    )

    assert response.status_code == 403

    delete_all_mock.assert_not_called()


def test_delete_refresh_token_not_found(app_not_found, test_client, delete_all_mock):
    response = test_client.delete(
        f"/token/refresh/12345",
        headers={"Authorization": f"Bearer fake-token"},
    )

    assert response.status_code == 404

    delete_all_mock.assert_not_called()
