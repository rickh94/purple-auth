import uuid


# TODO: test the routes are not accessible without api key


def test_get_public_key(test_client, fake_client_app, mocker):
    mock_export = mocker.patch(
        "app.routes.client_app.security_client_app.export_public_key",
        return_value={"fake": "key"},
    )
    response = test_client.get(
        f"/app/public_key/{fake_client_app.app_id}",
        headers={"Authorization": "Bearer testkey"},
    )

    assert response.status_code == 200
    assert response.json() == {"fake": "key"}
    mock_export.assert_called_once_with(fake_client_app)


def test_get_public_key_not_found(test_client, mocker, app_not_found):
    mock_export = mocker.patch(
        "app.routes.client_app.security_client_app.export_public_key",
        return_value={"fake": "key"},
    )
    response = test_client.get(
        f"/app/public_key/{uuid.uuid4()}", headers={"Authorization": "Bearer testkey"}
    )

    assert response.status_code == 404
    mock_export.assert_not_called()


def test_get_public_key_requires_api_key(test_client, mocker, fake_client_app):
    mock_export = mocker.patch(
        "app.routes.client_app.security_client_app.export_public_key",
        return_value={"fake": "key"},
    )
    response = test_client.get(
        f"/app/public_key/{fake_client_app.app_id}",
    )

    assert response.status_code == 401
    mock_export.assert_not_called()


def test_get_public_key_requires_correct_api_key(test_client, mocker, fake_client_app):
    mock_export = mocker.patch(
        "app.routes.client_app.security_client_app.export_public_key",
        return_value={"fake": "key"},
    )
    response = test_client.get(
        f"/app/public_key/{fake_client_app.app_id}",
        headers={"Authorization": "Bearer wrongkey"},
    )

    assert response.status_code == 401
    mock_export.assert_not_called()


def test_get_client_app(test_client, fake_client_app):
    response = test_client.get(
        f"/app/{fake_client_app.app_id}", headers={"Authorization": "Bearer testkey"}
    )

    assert response.status_code == 200
    response_app = response.json()
    assert response_app["app_id"] == fake_client_app.app_id
    assert response_app["redirect_url"] == fake_client_app.redirect_url
    assert response_app["name"] == fake_client_app.name
    assert response_app.get("key") is None


def test_get_app_not_found(test_client, app_not_found):
    response = test_client.get(f"/app/123456")

    assert response.status_code == 404


def test_get_client_app_requires_api_key(test_client, fake_client_app):
    response = test_client.get(f"/app/{fake_client_app.app_id}")

    assert response.status_code == 401
    assert "app_id" not in response.json()


def test_get_client_app_requires_correct_api_key(test_client, fake_client_app):
    response = test_client.get(
        f"/app/{fake_client_app.app_id}",
        headers={"Authorization": "Bearer wrongkey"},
    )

    assert response.status_code == 401
    assert "app_id" not in response.json()
