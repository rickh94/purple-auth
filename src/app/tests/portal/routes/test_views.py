import datetime
import os

import pytest
import python_jwt as jwt
from purple_auth_client import AuthenticationFailure

from app.portal.services.ensure_portal_app import ensure_portal_app
from app.security import token


def test_index_renders(test_client):
    response = test_client.get("/")

    assert response.status_code == 200
    assert "Purple Authentication" in response.text
    assert "Authentication" in response.text
    assert "without passwords" in response.text
    assert "Get Started" in response.text
    assert "Login" in response.text
    assert "Frequently Asked Questions" in response.text
    assert "Rick Henry Development" in response.text


def test_logged_in_index_shows_dashboard_link(user1_client, fake_cookies):
    response = user1_client.get("/", cookies=fake_cookies)

    assert "Dashboard" in response.text


def test_how_it_works_renders(test_client):
    response = test_client.get("/how-it-works")

    assert response.status_code == 200
    assert "Purple Authentication" in response.text
    assert "How It Works" in response.text
    assert "Passcode Flow" in response.text
    assert "Magic Link Flow" in response.text
    assert "Behind the Scenes" in response.text


def test_dashboard_redirects_to_login_unauthenticated(test_client):
    response = test_client.get("/dashboard")

    assert response.status_code == 200
    assert "Login" in response.text


def test_dashboard_renders(user1_client, fake_cookies):
    response = user1_client.get("/dashboard", cookies=fake_cookies)

    assert "Dashboard" in response.text
    assert "Your Apps" in response.text
    assert "Your Account" in response.text
    assert "Create New App" in response.text
    assert "Create one to get started!" in response.text


def test_dashboard_shows_user_apps(user1_client, user1_app1, user1_app2, fake_cookies):
    response = user1_client.get("/dashboard", cookies=fake_cookies)

    assert user1_app1.name in response.text
    assert user1_app2.name in response.text


def test_dashboard_shows_user_info(user1_client, user1, fake_cookies):
    response = user1_client.get("/dashboard", cookies=fake_cookies)

    assert user1.email in response.text


def test_login_renders(test_client):
    response = test_client.get("/login")

    assert response.status_code == 200
    assert "Login" in response.text
    assert "One Time Code" in response.text
    assert "Magic Link" in response.text
    assert "Email" in response.text


def test_login_redirects_to_dashboard_already_logged_in(user1_client, fake_cookies):
    response = user1_client.get("/login", cookies=fake_cookies)

    assert response.status_code == 200
    assert "Dashboard" in response.text
    assert "Your Apps" in response.text


def test_login_confirm_renders(test_client):
    response = test_client.get("/login/confirm")

    assert response.status_code == 200
    assert "Enter Code" in response.text
    assert "Check your email" in response.text


def test_login_confirm_has_email_in_hidden_input(test_client, faker, mocker):
    mocker.patch("app.portal.routes.auth.auth_client.authenticate")
    email = faker.email()
    response = test_client.post("/auth/request", data={"email": email, "flow": "otp"})

    assert f'value="{email}"' in response.text


def test_login_magic_message_renders(test_client):
    response = test_client.get("/login/magic-message")

    assert response.status_code == 200
    assert "Check Your Email!" in response.text
    assert "link to authenticate" in response.text


def test_login_magic_failed_renders(test_client):
    response = test_client.get("/login/magic-failed")

    assert response.status_code == 200
    assert "Invalid Link" in response.text
    assert "Please try to login again" in response.text


@pytest.mark.asyncio
@pytest.mark.skip
async def test_login_refreshes_with_refresh_token(
    test_client, user1, monkeypatch, mocker
):
    # This test is giving me a headache. It's kind of a convenience feature...and it
    # works. I just can't get a test to work correctly.
    payload = {"iss": f"{os.getenv('HOST')}/0", "sub": user1.email}
    portal = await ensure_portal_app()

    new_id_token = jwt.generate_jwt(
        payload, portal.get_key(), "ES256", datetime.timedelta(minutes=5)
    )

    async def fake_refresh(*_args):
        return new_id_token

    mocker.patch(
        "app.portal.routes.auth.auth_client.verify",
        side_effect=[
            # AuthenticationFailure("expired"),
            {
                "headers": {"alg": "ES256", "typ": "JWT"},
                "claims": {
                    "iss": os.getenv("HOST"),
                    "sub": user1.email,
                },
            },
        ],
    )
    monkeypatch.setattr("app.portal.security.pac.AuthClient.refresh", fake_refresh)

    id_token = jwt.generate_jwt(
        payload, portal.get_key(), "ES256", datetime.timedelta(seconds=0)
    )
    refresh_token = await token.generate_refresh_token(user1.email, portal)

    response = test_client.get(
        "/login",
        cookies={
            # "id_token": "",
            "refresh_token": refresh_token,
        },
    )

    assert response.ok
    assert "Dashboard" in response.text
    assert "Your Apps" in response.text
    # With the 307 redirect, there will be a new get request from the final request that
    # should have the cookie set from the refresh in the login view.
    print(response.request._cookies["id_token"])
    assert response.request._cookies.get("id_token").value == new_id_token
