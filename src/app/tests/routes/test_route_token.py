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
        f"/token/verify/{fake_client_app.app_id}?idToken=fake_token"
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
        f"/token/verify/{fake_client_app.app_id}?idToken=fake_token"
    )

    assert response.status_code == 401
    assert response.json().get("headers") is None
    assert response.json().get("claims") is None


def test_verify_token_not_found(app_not_found, test_client, mocker):
    verify_mock = mocker.patch(
        "app.routes.token.security_token.verify",
    )

    response = test_client.get(f"/token/verify/12345?idToken=fake_token")

    assert response.status_code == 404
    assert response.json().get("headers") is None
    assert response.json().get("claims") is None

    verify_mock.assert_not_called()
