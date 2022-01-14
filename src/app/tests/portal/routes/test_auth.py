import datetime

import mongox
import pytest
from mongox import Q
from purple_auth_client import AuthClientError

from app import config
from app.models.client_app_model import ClientApp
from app.models.token_models import RefreshToken
from app.portal.models.user_model import User
from app.portal.services import deletion_protection


def test_request_login_otp(mocker, test_client, faker):
    email = faker.email()
    mock_authenticate = mocker.patch("app.portal.routes.auth.auth_client.authenticate")

    response = test_client.post("/auth/request", data={"email": email, "flow": "otp"})

    assert response.ok
    mock_authenticate.assert_called_once_with(email, "otp")

    assert "Enter Code" in response.text, "Should show the OTP code form"


def test_request_login_magic(mocker, test_client, faker):
    email = faker.email()
    mock_authenticate = mocker.patch("app.portal.routes.auth.auth_client.authenticate")

    response = test_client.post("/auth/request", data={"email": email, "flow": "magic"})

    assert response.ok
    mock_authenticate.assert_called_once_with(email, "magic")

    # Check if the user was created in the database. Will raise mongox.NoMatchFound if
    # not.
    assert response.status_code == 303, "Should redirect to the magic link page"
    assert (
        response.headers["location"] == "/login/magic-message"
    ), "Should redirect to the magic link page"
    assert (
        response.headers["hx-redirect"] == "/login/magic-message"
    ), "Should hx redirect to the magic link page"
    assert (
        response.headers["hx-push"] == "/login/magic-message"
    ), "Should hx push to the magic link page"


@pytest.mark.asyncio
async def test_otp_request_login_existing_user(mocker, test_client, faker):
    user = await User(email=faker.email()).insert()
    mocker.patch("app.portal.routes.auth.auth_client.authenticate")

    response = test_client.post(
        "/auth/request", data={"email": user.email, "flow": "otp"}
    )

    assert response.ok


@pytest.mark.asyncio
async def test_magic_request_login_existing_user(mocker, test_client, faker):
    user = await User(email=faker.email()).insert()
    mocker.patch("app.portal.routes.auth.auth_client.authenticate")

    response = test_client.post(
        "/auth/request", data={"email": user.email, "flow": "magic"}
    )

    assert response.ok


def test_request_login_fails_invalid_flow(test_client, faker):
    response = test_client.post(
        "/auth/request", data={"email": faker.email(), "flow": "invalid"}
    )

    assert not response.ok
    assert "Invalid Auth Flow" in response.text


@pytest.mark.asyncio
async def test_request_otp_login_creates_user(mocker, test_client, faker):
    email = faker.email()
    mocker.patch("app.portal.routes.auth.auth_client.authenticate")

    # This should raise because the user doesn't exist yet
    with pytest.raises(mongox.NoMatchFound):
        await User.query(User.email == email).get()
    response = test_client.post("/auth/request", data={"email": email, "flow": "otp"})

    assert response.ok
    # Check if the user was created in the database. Will raise mongox.NoMatchFound if
    # not.
    await User.query(User.email == email).get()


@pytest.mark.asyncio
async def test_request_magic_login_creates_user(mocker, test_client, faker):
    email = faker.email()
    mocker.patch("app.portal.routes.auth.auth_client.authenticate")

    # This should raise because the user doesn't exist yet
    with pytest.raises(mongox.NoMatchFound):
        await User.query(User.email == email).get()
    response = test_client.post("/auth/request", data={"email": email, "flow": "magic"})

    assert response.ok
    # Check if the user was created in the database. Will raise mongox.NoMatchFound if
    # not.
    await User.query(User.email == email).get()


def test_confirm_otp_success(mocker, test_client, faker):
    mock_submit_code = mocker.patch(
        "app.portal.routes.auth.auth_client.submit_code",
        return_value={
            "id_token": "fake_id_token",
            "refresh_token": "fake_refresh_token",
        },
    )

    email = faker.email()
    response = test_client.post("/auth/confirm", data={"otp": "123456", "email": email})

    assert response.ok
    assert response.cookies.get("id_token") == "fake_id_token"
    assert response.cookies.get("refresh_token") == "fake_refresh_token"

    mock_submit_code.assert_called_once_with(email, "123456")

    assert response.headers.get("location") == "/dashboard"
    assert response.headers.get("hx-redirect") == "/dashboard"
    assert response.headers.get("hx-push") == "/dashboard"


def test_confirm_otp_failure_stays_on_page_and_shows_message(
    mocker, test_client, faker
):
    mock_submit_code = mocker.patch(
        "app.portal.routes.auth.auth_client.submit_code", side_effect=[AuthClientError]
    )

    email = faker.email()
    response = test_client.post("/auth/confirm", data={"otp": "123456", "email": email})

    assert response.ok
    assert "Invalid code" in response.text
    assert "Enter Code" in response.text

    mock_submit_code.assert_called_once_with(email, "123456")

    assert "location" not in response.headers


def test_confirm_magic_success(test_client, faker, mocker):
    mocker.patch(
        "app.portal.routes.views.DashboardVM.check_for_user", return_value=True
    )
    mocker.patch("app.portal.routes.views.DashboardVM.get_user_apps", return_value=[])
    response = test_client.get(
        "/auth/confirm/magic?idToken=fakeidtoken&refreshToken=fakerefreshtoken"
    )

    assert response.ok
    assert response.request._cookies.get("id_token") == "fakeidtoken"
    assert response.request._cookies.get("refresh_token") == "fakerefreshtoken"
    assert "Your Apps" in response.text


def test_logout_deletes_token(test_client, faker, mocker):
    mocker.patch("app.portal.routes.views.IndexVM.check_for_user")
    mock_delete_cookie = mocker.patch(
        "app.portal.services.auth.RedirectResponse.delete_cookie"
    )
    response = test_client.get(
        "/auth/logout", cookies={"id_token": "fakeidtoken", "refresh_token": None}
    )

    assert response.ok
    assert response.cookies.get("id_token") is None
    assert "Authentication" in response.text
    assert "without passwords" in response.text
    mock_delete_cookie.assert_any_call("id_token")


def test_logout_deletes_refresh_token(test_client, faker, mocker):
    mocker.patch("app.portal.routes.views.IndexVM.check_for_user")
    mock_delete_cookie = mocker.patch(
        "app.portal.services.auth.RedirectResponse.delete_cookie"
    )
    mock_delete_refresh_token = mocker.patch(
        "app.portal.services.auth.auth_client.delete_refresh_token"
    )
    response = test_client.get(
        "/auth/logout",
        cookies={"id_token": "fakeidtoken", "refresh_token": "fakerefreshtoken"},
    )

    assert response.ok

    mock_delete_refresh_token.assert_called_once_with("fakeidtoken", "fakerefreshtoken")
    mock_delete_cookie.assert_any_call("refresh_token")


def test_logout_everywhere_works(mocker, test_client, faker):
    mocker.patch("app.portal.routes.views.IndexVM.check_for_user")
    mock_delete_cookie = mocker.patch(
        "app.portal.services.auth.RedirectResponse.delete_cookie"
    )
    mock_delete_refresh_token = mocker.patch(
        "app.portal.services.auth.auth_client.delete_all_refresh_tokens"
    )
    response = test_client.get(
        "/auth/logout-everywhere",
        cookies={"id_token": "fakeidtoken", "refresh_token": "fakerefreshtoken"},
    )

    assert response.ok

    mock_delete_refresh_token.assert_called_once_with("fakeidtoken")
    mock_delete_cookie.assert_any_call("id_token")
    mock_delete_cookie.assert_any_call("refresh_token")


@pytest.mark.asyncio
async def test_update_user_success(
    user1, user1_client, faker, monkeypatch, fake_cookies
):
    name = faker.name()

    response = user1_client.put("/auth/me", data={"name": name}, cookies=fake_cookies)

    assert response.ok
    assert "Account Updated" in response.headers.get(
        "HX-Trigger"
    ), "Should show notification"
    assert name in response.text, "New name should be in replacement html"
    assert user1.email in response.text, "Email should be in replacement html"

    updated_user = await User.query(User.email == user1.email).get()

    assert updated_user.name == name


def test_update_user_fails_unauthenticated(test_client, faker):
    response = test_client.put("/auth/me", data={"name": faker.name()})

    assert not response.ok
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_cannot_change_user_email(user1_client, faker, fake_cookies, user1):
    new_email = faker.email()
    old_email = user1.email
    assert new_email != old_email, "Just in case"
    response = user1_client.put(
        "/auth/me",
        data={"name": faker.name(), "email": new_email},
        cookies=fake_cookies,
    )

    assert response.ok

    # Check that the email has not changed. If the user's email has changed, this will
    # throw mongox.NoMatchFound
    await User.query(User.email == old_email).get()

    with pytest.raises(mongox.NoMatchFound):
        await User.query(User.email == new_email).get()


def test_delete_shows_deletion_protection_warning(user1_client, fake_cookies):
    response = user1_client.get("/auth/me/delete", cookies=fake_cookies)

    assert response.ok
    assert "Disable Deletion Protection" in response.text
    assert "Get Code" in response.text


def test_get_delete_form_fails_unauthenticated(test_client):
    response = test_client.get("/auth/me/delete")

    assert not response.ok
    assert response.status_code == 401


def test_start_deletion_protection_sends_email(
    user1_client, fake_cookies, mocker, user1
):
    mocker.patch(
        "app.portal.routes.auth.deletion_protection.generate_dp_code",
        return_value="123456",
    )
    mock_send_email = mocker.patch("app.portal.routes.auth.io_email.send")
    response = user1_client.get("/auth/me/deletion-protection", cookies=fake_cookies)

    assert response.ok
    assert "Check your email" in response.text, "Should show confirm form."
    assert "Confirm" in response.text

    mock_send_email.assert_called_once_with(
        to=user1.email,
        subject="Deletion Protection Code",
        text=f"Enter this code to disable deletion protection "
        f"for your user account: 123456. This code will expire in "
        f"{config.OTP_LIFETIME} minutes.",
        from_name="Purple Authentication",
        reply_to=config.WEBMASTER_EMAIL,
    )


def test_start_deletion_protection_fails_unauthenticated(test_client, mocker):
    mock_send_email = mocker.patch("app.portal.routes.auth.io_email.send")
    response = test_client.get("/auth/me/deletion-protection")

    assert not response.ok
    assert response.status_code == 401

    mock_send_email.assert_not_called()


def test_disable_deletion_protection_succeeds(user1_client, fake_cookies, user1):
    code = deletion_protection.generate_dp_code(user1, "account")

    response = user1_client.post(
        "/auth/me/deletion-protection", data={"code": code}, cookies=fake_cookies
    )

    assert response.ok

    assert (
        "Deletion Protection Disabled" in response.headers["HX-Trigger"]
    ), "Should show notification"
    assert "closeModal" in response.headers["HX-Trigger"], "Should close modal"


def test_disable_deletion_protection_fails_unauthorized(test_client):
    response = test_client.post("/auth/me/deletion-protection", data={"code": "123456"})

    assert not response.ok
    assert response.status_code == 401


def test_disable_deletion_protection_fails_wrong_code(
    user1_client, fake_cookies, user1
):
    # This just ensures that there is a code and it fails because it doesn't match
    deletion_protection.generate_dp_code(user1, "account")

    response = user1_client.post(
        "/auth/me/deletion-protection", data={"code": "123456"}, cookies=fake_cookies
    )

    assert not response.ok
    assert response.status_code == 400
    assert "Invalid deletion protection code" in response.text


@pytest.mark.asyncio
async def test_delete_user_shows_confirm_delete(
    deletable_user, deletable_user_client, fake_cookies
):
    await deletable_user.insert()
    response = deletable_user_client.get("/auth/me/delete", cookies=fake_cookies)

    assert response.ok
    assert (
        "Delete My Account" in response.text
    ), "Should show deletion form, not the deletion protection form."
    assert "Protection" not in response.text


@pytest.mark.asyncio
async def test_delete_user_works(deletable_user, deletable_user_client, fake_cookies):
    await deletable_user.insert()
    response = deletable_user_client.post("/auth/me/delete", cookies=fake_cookies)

    assert response.ok
    assert response.status_code == 303
    assert response.headers["location"] == "/?accountDeleted=true"
    assert response.headers["hx-redirect"] == "/?accountDeleted=true"
    assert response.headers["hx-push"] == "/?accountDeleted=true"

    with pytest.raises(mongox.NoMatchFound):
        await User.query(User.email == deletable_user.email).get()


@pytest.mark.asyncio
async def test_delete_user_fails_deletion_protection_enabled(
    user1, user1_client, fake_cookies
):
    await user1.insert()
    response = user1_client.post("/auth/me/delete", cookies=fake_cookies)

    assert not response.ok
    print(response.text)
    assert response.status_code == 400
    assert (
        "You need to turn off deletion protection to delete your account."
        in response.text
    )

    # This will raise mongox.NoMatchFound if the user has been deleted
    await User.query(User.email == user1.email).get()


def test_delete_user_fails_unauthenticated(test_client):
    response = test_client.post("/auth/me/delete")

    assert not response.ok
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delete_user_deletes_user_apps(
    deletable_user,
    deletable_user_client,
    deletable_user_app1,
    deletable_user_app2,
    fake_cookies,
):
    await deletable_user.insert()

    user_apps_before_delete = await ClientApp.query(
        ClientApp.owner == deletable_user.email
    ).all()

    assert len(user_apps_before_delete) > 0

    response = deletable_user_client.post("/auth/me/delete", cookies=fake_cookies)

    assert response.ok

    user_apps_after_delete = await ClientApp.query(
        ClientApp.owner == deletable_user.email
    ).all()

    assert not user_apps_after_delete


@pytest.mark.asyncio
async def test_delete_user_deletes_user_app_refresh_tokens(
    deletable_user,
    deletable_user_client,
    deletable_user_app1,
    deletable_user_app2,
    fake_cookies,
    faker,
):
    await deletable_user.insert()
    date_in_future = datetime.datetime.now() + datetime.timedelta(days=1)
    for _ in range(5):
        await RefreshToken(
            app_id=deletable_user_app1.app_id,
            email=faker.email(),
            hash="fakehash",
            expires=date_in_future,
            uid="fakeuid",
        ).insert()

    for _ in range(5):
        await RefreshToken(
            app_id=deletable_user_app2.app_id,
            email=faker.email(),
            hash="fakehash",
            expires=date_in_future,
            uid="fakeuid",
        ).insert()

    refresh_tokens_before_delete = await RefreshToken.query(
        Q.in_(
            RefreshToken.app_id,
            [deletable_user_app1.app_id, deletable_user_app2.app_id],
        )
    ).all()

    assert len(refresh_tokens_before_delete) > 0

    response = deletable_user_client.post("/auth/me/delete", cookies=fake_cookies)

    assert response.ok

    refresh_tokens_after_delete = await RefreshToken.query(
        Q.in_(
            RefreshToken.app_id,
            [deletable_user_app1.app_id, deletable_user_app2.app_id],
        )
    ).all()

    assert not refresh_tokens_after_delete
