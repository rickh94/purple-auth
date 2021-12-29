from urllib.parse import quote_plus

import purple_auth_client as pac
from fastapi import APIRouter, Form, HTTPException, Query
from fastapi.params import Depends
from starlette import status
from starlette.requests import Request
from starlette.responses import RedirectResponse

from app.portal.crud import user_crud
from app.portal.models.user_model import User, UserPublic
from app.portal.security import auth_client, oauth2_scheme, get_current_active_user
from app.portal.services.auth import (
    make_authenticated_response,
    handle_logout,
    handle_logout_everywhere,
    make_logged_out_response,
)

portal_auth_router = APIRouter()


@portal_auth_router.post("/request")
async def request_login(email: str = Form(...), flow: str = Form(...)):
    """
    Request a login code or link. This will start the login process.

    :param email:  Email address entered by user
    :param flow: Either "otp" or "magic" to indicate either one time passcode or
    magic link authentication flow
    :return: redirect to the appropriate page to continue the login process
    """
    try:
        await user_crud.check_or_create_user_from_email(email)
        await auth_client.authenticate(email, flow)
    except pac.InvalidAuthFlow as e:
        raise HTTPException(status_code=400, detail=str(e))
    except pac.AuthClientError:
        raise HTTPException(status_code=500, detail="Internal Error, try again later")
    if flow == "otp":
        return RedirectResponse(
            f"/login/confirm?email={quote_plus(email)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    elif flow == "magic":
        return RedirectResponse(
            "/login/magic-message",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    # Currently, the only valid auth flows are "otp" and "magic." If something else
    # is provided, it should raise "InvalidAuthFlow," therefore this code should be
    # unreachable.
    raise HTTPException(status_code=500, detail="Something has gone wrong")


@portal_auth_router.post("/confirm")
async def confirm_otp_login(
    email: str = Form(...), otp: str = Form(...), stay_logged_in: bool = Form(False)
):
    """
    Process and confirm user login using one time passcode.

    :param email: Email address previously entered by the user
    :param otp: One time passcode entered by user
    :return: redirect to the appropriate page to continue the login process
    """
    try:
        tokens = await auth_client.submit_code(email, otp)
        return make_authenticated_response(
            "/dashboard",
            tokens["id_token"],
            tokens.get("refresh_token"),
            stay_logged_in,
        )
    except pac.AuthClientError:
        return RedirectResponse(
            f"/confirm?error={quote_plus('Could not validate code')}"
            f"&email={quote_plus(email)}"
        )


@portal_auth_router.get("/confirm/magic")
async def confirm_magic(
    id_token: str = Query(..., alias="idToken"),
    refresh_token: str = Query(None, alias="refreshToken"),
):
    """
    Sets the user's id token and refresh token cookies and redirects to the dashboard.

    :param id_token: ID token returned by the auth server
    :param refresh_token: Refresh token returned by the auth server
    :return: redirect to the appropriate page to continue the login process
    """
    return make_authenticated_response("/dashboard", id_token, refresh_token)


@portal_auth_router.get("/logout")
async def logout(request: Request):
    """
    Logout User
    :param request: request from the server
    :return: redirect to index
    """
    id_token = request.cookies.get(oauth2_scheme.token_name)
    refresh_token = request.cookies.get(oauth2_scheme.refresh_token_name)

    response = make_logged_out_response("Logged Out")

    if not refresh_token:
        return response

    await handle_logout(id_token, refresh_token)
    return response


@portal_auth_router.get("/logout-everywhere")
async def logout_everywhere(request: Request):
    """
    Logout user from all devices (invalidated all refresh tokens).

    :param request: request from the server
    :return: redirect to index
    """
    response = make_logged_out_response("Logged Out from all devices")

    id_token = request.cookies.get(oauth2_scheme.token_name)
    await handle_logout_everywhere(id_token)

    return response


@portal_auth_router.get("/me", response_model=UserPublic)
async def me(current_user: User = Depends(get_current_active_user)):
    """
    Get information about a user

    :param current_user: User from the database
    :return: the user
    """
    # TODO: remove database id
    return current_user


@portal_auth_router.delete("/me")
async def delete_me(current_user: User = Depends(get_current_active_user)):
    """
    Delete a user's information from the database

    :param current_user: User from the database
    :return: None
    """
    await user_crud.delete_user(current_user)
