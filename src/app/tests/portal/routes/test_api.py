import os

import mongox
import pytest

from app.io.email import EmailError
from app.models.client_app_model import ClientApp
from app.models.token_models import RefreshToken
from app.security.token import generate_refresh_token


# CREATE


def test_get_create_app_form(user1_client, fake_cookies):
    response = user1_client.get("/api/apps/create", cookies=fake_cookies)

    assert response.ok
    assert response.status_code == 200

    assert "Create App" in response.text
    assert "App Name" in response.text
    assert "Refresh Enabled" in response.text
    assert "Magic Link Redirect URL" in response.text
    assert "Magic Link Failure Redirect URL" in response.text
    assert "Low Quota Notification Threshold" in response.text
    assert "Save" in response.text


def test_get_create_app_form_fails_unauthenticated(test_client):
    pass


def test_create_app_successful(user1_client, fake_cookies):
    response = user1_client.post(
        "/api/apps/create",
        data={
            "app_name": "Test App 1",
            "redirect_url": "https://example.com/magic",
            "failure_redirect_url": "https://example.com/fail",
            "refresh": True,
        },
        cookies=fake_cookies,
    )

    assert response.status_code == 201
    assert "Test App 1" in response.text
    assert "closeModal" in response.headers["HX-Trigger"]
    assert "App Created" in response.headers["HX-Trigger"]
    assert "showApp" in response.headers["HX-Trigger-After-Settle"]


def test_create_app_fails_not_authenticated(test_client):
    response = test_client.post(
        "/api/apps/create",
        data={
            "app_name": "Test App 1",
            "redirect_url": "https://example.com/magic",
            "failure_redirect_url": "https://example.com/fail",
            "refresh": True,
        },
    )

    assert response.status_code == 401


# READ


def test_get_app_display_has_data(user1_client, user1_app1, fake_cookies):
    response = user1_client.get(f"/api/apps/{user1_app1.app_id}", cookies=fake_cookies)

    assert response.status_code == 200
    assert user1_app1.name in response.text
    assert user1_app1.app_id in response.text
    assert user1_app1.redirect_url in response.text
    assert user1_app1.failure_redirect_url in response.text
    assert str(user1_app1.quota) in response.text
    assert str(user1_app1.low_quota_threshold) in response.text


def test_get_app_display_fails_not_authenticated(test_client, user1_app1):
    response = test_client.get(f"/api/apps/{user1_app1.app_id}")

    assert response.status_code == 401


def test_get_app_fails_different_user(user2_client, user1_app1, fake_cookies):
    response = user2_client.get(f"/api/apps/{user1_app1.app_id}", cookies=fake_cookies)

    assert response.status_code == 404


# UPDATE


@pytest.mark.asyncio
async def test_update_app_succeeds(user1_app2, user1_client, fake_cookies):
    form_data = {
        "app_name": "updated name",
        "redirect_url": "https://updated.com",
        "failure_redirect_url": "https://updated.com/failed",
        "refresh_enabled": True,
    }

    response = user1_client.put(
        f"/api/apps/{user1_app2.app_id}",
        cookies=fake_cookies,
        data=form_data,
    )

    assert response.status_code == 200
    assert "App Updated" in response.headers["HX-Trigger"]
    assert "closeModal" in response.headers["HX-Trigger"]
    assert "showApp" in response.headers["HX-Trigger-After-Settle"]

    updated_app = await ClientApp.query(ClientApp.app_id == user1_app2.app_id).get()

    assert updated_app.name == form_data["app_name"]
    assert updated_app.redirect_url == form_data["redirect_url"]
    assert updated_app.failure_redirect_url == form_data["failure_redirect_url"]


@pytest.mark.asyncio
async def test_update_app_enable_refresh(
    user1_app_no_refresh, user1_client, fake_cookies
):
    form_data = {
        "app_name": "updated name",
        "redirect_url": "https://updated.com",
        "failure_redirect_url": "https://updated.com/failed",
        "refresh_enabled": True,
    }

    assert user1_app_no_refresh.enc_refresh_key is None

    response = user1_client.put(
        f"/api/apps/{user1_app_no_refresh.app_id}", cookies=fake_cookies, data=form_data
    )

    assert response.status_code == 200

    updated_app = await ClientApp.query(
        ClientApp.app_id == user1_app_no_refresh.app_id
    ).get()

    assert updated_app.enc_refresh_key is not None
    assert updated_app.refresh_token_expire_hours is not None


@pytest.mark.asyncio
async def test_update_app_disable_refresh(user1_app3, user1_client, fake_cookies):
    form_data = {
        "app_name": "updated name",
        "redirect_url": "https://updated.com",
        "failure_redirect_url": "https://updated.com/failed",
        "refresh_enabled": False,
    }

    assert user1_app3.enc_refresh_key is not None

    response = user1_client.put(
        f"/api/apps/{user1_app3.app_id}", cookies=fake_cookies, data=form_data
    )

    assert response.status_code == 200

    updated_app = await ClientApp.query(ClientApp.app_id == user1_app3.app_id).get()

    assert updated_app.enc_refresh_key is None


def test_update_app_fails_unauthorized(user1_app1, user2_client, fake_cookies):
    form_data = {
        "app_name": "updated name",
        "redirect_url": "https://updated.com",
        "failure_redirect_url": "https://updated.com/failed",
        "refresh_enabled": False,
    }

    response = user2_client.put(
        f"/api/apps/{user1_app1.app_id}", cookies=fake_cookies, data=form_data
    )

    assert response.status_code == 404


def test_update_app_fails_unauthenticated(user1_app1, test_client):
    form_data = {
        "app_name": "updated name",
        "redirect_url": "https://updated.com",
        "failure_redirect_url": "https://updated.com/failed",
        "refresh_enabled": False,
    }

    response = test_client.put(f"/api/apps/{user1_app1.app_id}", data=form_data)

    assert response.status_code == 401


def test_get_rotate_app_keys_returns_form(user1_app1, user1_client, fake_cookies):
    response = user1_client.get(
        f"/api/apps/{user1_app1.app_id}/rotate-keys", cookies=fake_cookies
    )

    assert response.status_code == 200

    assert "Change Keys" in response.text
    assert f"Reset {user1_app1.name} Keys" in response.text


def test_get_rotate_app_keys_fails_unauthorized(user2_client, user1_app1, fake_cookies):
    response = user2_client.get(
        f"/api/apps/{user1_app1.app_id}/rotate-keys", cookies=fake_cookies
    )

    assert response.status_code == 404


def test_get_rotate_app_keys_fails_unauthenticated(test_client, user1_app1):
    response = test_client.get(f"/api/apps/{user1_app1.app_id}/rotate-keys")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_rotate_keys_rotates_main_key(user1_client, user1_app1, fake_cookies):
    old_key = user1_app1.get_key()

    response = user1_client.post(
        f"/api/apps/{user1_app1.app_id}/rotate-keys", cookies=fake_cookies
    )

    assert response.status_code == 200
    assert not response.text
    assert "App Keys Changed" in response.headers["HX-Trigger"]
    assert "closeModal" in response.headers["HX-Trigger"]

    updated_app = await ClientApp.query(ClientApp.app_id == user1_app1.app_id).get()

    assert updated_app.get_key() != old_key


@pytest.mark.asyncio
async def test_rotate_keys_rotates_refresh_key(user1_client, user1_app1, fake_cookies):
    old_key = user1_app1.get_refresh_key()

    response = user1_client.post(
        f"/api/apps/{user1_app1.app_id}/rotate-keys", cookies=fake_cookies
    )

    assert response.status_code == 200

    updated_app = await ClientApp.query(ClientApp.app_id == user1_app1.app_id).get()

    assert updated_app.get_refresh_key() != old_key


@pytest.mark.asyncio
async def test_rotate_keys_fails_unauthorized(user2_client, user1_app1, fake_cookies):
    old_key = user1_app1.get_key()
    old_refresh_key = user1_app1.get_refresh_key()

    response = user2_client.post(
        f"/api/apps/{user1_app1.app_id}/rotate-keys", cookies=fake_cookies
    )

    assert response.status_code == 404

    updated_app = await ClientApp.query(ClientApp.app_id == user1_app1.app_id).get()

    assert updated_app.get_key() == old_key
    assert updated_app.get_refresh_key() == old_refresh_key


@pytest.mark.asyncio
async def test_rotate_keys_fails_unauthenticated(test_client, user1_app1):
    old_key = user1_app1.get_key()
    old_refresh_key = user1_app1.get_refresh_key()

    response = test_client.post(f"/api/apps/{user1_app1.app_id}/rotate-keys")

    assert response.status_code == 401

    updated_app = await ClientApp.query(ClientApp.app_id == user1_app1.app_id).get()

    assert updated_app.get_key() == old_key
    assert updated_app.get_refresh_key() == old_refresh_key


# DELETE


def test_get_delete_app_returns_deletion_protection(
    user1_app1, user1_client, fake_cookies
):
    response = user1_client.get(
        f"/api/apps/{user1_app1.app_id}/delete", cookies=fake_cookies
    )

    assert response.status_code == 200
    assert "Disable Deletion Protection" in response.text
    assert "Get Code" in response.text
    assert "Before you can delete this app" in response.text


def test_get_delete_app_returns_form_protection_disabled(
    user1_app_unprotected, user1_client, fake_cookies
):
    app = user1_app_unprotected

    response = user1_client.get(f"/api/apps/{app.app_id}/delete", cookies=fake_cookies)

    assert response.status_code == 200
    assert "Delete App" in response.text
    assert f"Delete {app.name}" in response.text


def test_get_delete_app_fails_unauthenticated(test_client, user1_app1):
    response = test_client.get(f"/api/apps/{user1_app1.app_id}/delete")

    assert response.status_code == 401


def test_get_delete_app_fails_unauthorized(user2_client, user1_app1, fake_cookies):
    response = user2_client.get(
        f"/api/apps/{user1_app1.app_id}/delete", cookies=fake_cookies
    )

    assert response.status_code == 404


def test_get_deletion_protection_sends_email(
    user1_client, user1_app1, fake_cookies, mocker, user1, monkeypatch
):
    mock_send_email = mocker.patch("app.io.email.send")
    monkeypatch.setattr(
        "app.portal.services.deletion_protection.secrets.choice", lambda x: "1"
    )

    response = user1_client.get(
        f"/api/apps/{user1_app1.app_id}/deletion-protection", cookies=fake_cookies
    )

    assert response.status_code == 200
    assert "Disable Deletion Protection" in response.text
    assert "Check your email" in response.text
    assert "Confirm" in response.text

    code = "1" * int(os.getenv("OTP_LENGTH", "6"))
    lifetime = int(os.getenv("OTP_LIFETIME", "5"))

    mock_send_email.assert_called_once_with(
        to=user1.email,
        subject="Deletion Protection Code",
        text=f"Enter this code to disable deletion protection "
        f"for {user1_app1.name}: {code}. This code will expire in "
        f"{lifetime} minutes.",
        from_name="Purple Authentication",
        reply_to=os.getenv("WEBMASTER_EMAIL"),
    )


def test_get_deletion_protection_send_email_fails(
    user1_client, user1_app1, fake_cookies, mocker, user1, monkeypatch
):
    mocker.patch("app.io.email.send", side_effect=[EmailError("Test Error")])

    response = user1_client.get(
        f"/api/apps/{user1_app1.app_id}/deletion-protection", cookies=fake_cookies
    )

    assert response.status_code == 500


@pytest.mark.asyncio
async def test_disable_deletion_protection_succeeds(
    mocker, monkeypatch, user1_client, user1_app1, fake_cookies
):
    mocker.patch("app.io.email.send")
    monkeypatch.setattr(
        "app.portal.services.deletion_protection.secrets.choice", lambda x: "1"
    )

    user1_client.get(
        f"/api/apps/{user1_app1.app_id}/deletion-protection", cookies=fake_cookies
    )

    code = "1" * int(os.getenv("OTP_LENGTH", "6"))

    response = user1_client.post(
        f"/api/apps/{user1_app1.app_id}/deletion-protection",
        data={"code": code},
        cookies=fake_cookies,
    )

    assert response.status_code == 200

    assert user1_app1.name in response.text
    assert "Disabled" in response.text

    updated = await ClientApp.query(ClientApp.app_id == user1_app1.app_id).get()

    assert updated.deletion_protection is False


@pytest.mark.asyncio
async def test_disable_deletion_protection_fails_wrong_code(
    mocker, monkeypatch, user1_app1, user1_client, fake_cookies
):
    mocker.patch("app.io.email.send")
    monkeypatch.setattr(
        "app.portal.services.deletion_protection.secrets.choice", lambda x: "1"
    )

    user1_client.get(
        f"/api/apps/{user1_app1.app_id}/deletion-protection", cookies=fake_cookies
    )

    code = "2" * int(os.getenv("OTP_LENGTH", "6"))

    response = user1_client.post(
        f"/api/apps/{user1_app1.app_id}/deletion-protection",
        data={"code": code},
        cookies=fake_cookies,
    )

    assert response.status_code == 400

    assert "Invalid deletion protection code" in response.text

    updated = await ClientApp.query(ClientApp.app_id == user1_app1.app_id).get()

    assert updated.deletion_protection is True


def test_disable_deletion_protection_fails_unauthorized(
    user1_app1, user2_client, fake_cookies
):
    response = user2_client.post(
        f"/api/apps/{user1_app1.app_id}/deletion-protection",
        cookies=fake_cookies,
        data={"code": "111111"},
    )

    assert response.status_code == 404


def test_disable_deletion_protection_fails_unauthenticated(user1_app1, test_client):
    response = test_client.post(
        f"/api/apps/{user1_app1.app_id}/deletion-protection", data={"code": "111111"}
    )

    assert response.status_code == 401


def test_cannot_delete_portal_app(superuser_client):
    response = superuser_client.delete(f"/api/apps/0")

    assert response.status_code == 400
    assert "Cannot delete the portal app." in response.text


@pytest.mark.asyncio
async def test_delete_app(user1_client, user1_app_unprotected, fake_cookies):
    app_id = user1_app_unprotected.app_id

    response = user1_client.delete(
        f"/api/apps/{app_id}",
        cookies=fake_cookies,
        headers={"HX-Target": f"app-{app_id}"},
    )

    assert response.status_code == 204
    assert not response.text
    assert "closeModal" in response.headers["HX-Trigger"]
    assert "App Deleted" in response.headers["HX-Trigger"]
    assert "removeApp" in response.headers["HX-Trigger"]

    with pytest.raises(mongox.NoMatchFound):
        await ClientApp.query(ClientApp.app_id == app_id).get()


@pytest.mark.asyncio
async def test_delete_app_deletes_refresh_keys(
    user1_client, user1_app_unprotected, fake_cookies, faker
):
    app_id = user1_app_unprotected.app_id

    await generate_refresh_token(faker.email(), user1_app_unprotected)
    await generate_refresh_token(faker.email(), user1_app_unprotected)
    await generate_refresh_token(faker.email(), user1_app_unprotected)
    await generate_refresh_token(faker.email(), user1_app_unprotected)

    response = user1_client.delete(
        f"/api/apps/{app_id}",
        cookies=fake_cookies,
        headers={"HX-Target": f"app-{app_id}"},
    )

    assert response.status_code == 204

    found_tokens = await RefreshToken.query(RefreshToken.app_id == app_id).all()
    assert len(found_tokens) == 0


@pytest.mark.asyncio
async def delete_app_fails_protection_enabled(user1_client, user1_app1, fake_cookies):
    response = user1_client.delete(
        f"/api/apps/{user1_app1.app_id}",
        cookies=fake_cookies,
        headers={"HX-Target": f"app-{user1_app1.app_id}"},
    )

    assert response.status_code == 400

    # If the app was deleted, this will raise mongox.NoMatchFound and fail the test.
    await ClientApp.query(ClientApp.app_id == user1_app1.app_id).get()


def test_delete_app_fails_unauthenticated(test_client, user1_app_unprotected):
    response = test_client.delete(
        f"/api/apps/{user1_app_unprotected.app_id}", headers={"HX-Target": "app-1"}
    )

    assert response.status_code == 401


def test_delete_app_fails_unauthorized(
    user2_client, user1_app_unprotected, fake_cookies
):
    response = user2_client.delete(
        f"/api/apps/{user1_app_unprotected.app_id}",
        cookies=fake_cookies,
        headers={"HX-Target": "app-1"},
    )

    assert response.status_code == 404
