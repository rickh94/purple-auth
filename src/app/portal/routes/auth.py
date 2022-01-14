import purple_auth_client as pac
from fastapi import APIRouter, Form, HTTPException, Query, Response
from fastapi.params import Depends
from starlette import status
from starlette.requests import Request

from app import config
from app.portal.crud import user_crud
from app.portal.models.user_model import User, UserPublic
from app.portal.services import htmx, deletion_protection
from app.portal.services.templates import templates
from app.portal.security import auth_client, oauth2_scheme, get_current_active_user
from app.portal.services.auth import (
    make_authenticated_response,
    handle_logout,
    handle_logout_everywhere,
    make_logged_out_response,
    make_redirect_response,
)
from app.portal.viewmodels.base_vm import VMBase
from app.portal.viewmodels.confirmcode_vm import ConfirmCodeVM
import app.io.email as io_email

portal_auth_router = APIRouter()


@portal_auth_router.post("/request")
async def request_login(
    request: Request, email: str = Form(...), flow: str = Form(...)
):
    """
    Request a login code or link. This will start the login process.

    :param request: request from the server
    :param email:  Email address entered by user
    :param flow: Either "otp" or "magic" to indicate either one time passcode or
    magic link authentication flow
    :return: redirect to the appropriate page to continue the login process
    """
    try:
        await user_crud.check_or_create_user_from_email(email)
        await auth_client.authenticate(email, flow)
    except pac.InvalidAuthFlow:
        raise HTTPException(status_code=400, detail="Invalid Auth Flow")
    except pac.AuthClientError:
        raise HTTPException(status_code=500, detail="Internal Error, try again later")
    if flow == "otp":
        vm = ConfirmCodeVM(request, email)
        return templates.TemplateResponse("login/confirm_code.html", vm.to_dict())
    elif flow == "magic":
        return make_redirect_response(
            "/login/magic-message",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    # Currently, the only valid auth flows are "otp" and "magic." If something else
    # is provided, it should raise "InvalidAuthFlow," therefore this code should be
    # unreachable.
    raise HTTPException(status_code=500, detail="Something has gone wrong")


@portal_auth_router.post("/confirm")
async def confirm_otp_login(
    request: Request,
    email: str = Form(...),
    otp: str = Form(...),
    stay_logged_in: bool = Form(False),
):
    """
    Process and confirm user login using one time passcode.

    :param request: request from the server
    :param email: Email address previously entered by the user
    :param otp: One time passcode entered by user
    :param stay_logged_in: Whether the user wants to stay logged in
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
        vm = ConfirmCodeVM(request, email, error="Invalid code")
        return templates.TemplateResponse("login/confirm_code.html", vm.to_dict())


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

    response = make_logged_out_response()

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
    response = make_logged_out_response()

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
    return current_user


@portal_auth_router.put("/me")
async def update_me(
    request: Request,
    name: str = Form(...),
    current_user: User = Depends(get_current_active_user),
):
    """
    Update information about a user. User emails can't be changed programmatically
    right now.

    :param request: request from the server
    :param name: The user's new name
    :param current_user: User from the database
    :return: the user
    """
    updated_user = await user_crud.update_user(current_user, name)
    vm = VMBase(request=request, user=updated_user)
    res = templates.TemplateResponse("dashboard/user_account.html", vm.to_dict())
    res.headers["HX-Trigger"] = htmx.make_show_notification_header(
        res.headers,
        "Account Updated",
        "Your account has been updated successfully.",
        "success",
    )
    return res


@portal_auth_router.get("/me/delete")
async def delete_user_form(
    request: Request, user: User = Depends(get_current_active_user)
):
    vm = VMBase(request, user=user)
    if user.deletion_protection:
        return templates.TemplateResponse(
            "dashboard/account_deletion_protection_warning.html",
            vm.to_dict(),
            headers={"HX-Trigger-After-Settle": "openModal"},
        )
    return templates.TemplateResponse(
        "dashboard/account_delete.html",
        vm.to_dict(),
        headers={"HX-Trigger-After-Settle": "openModal"},
    )


@portal_auth_router.post("/me/delete")
async def delete_me(current_user: User = Depends(get_current_active_user)):
    """
    Delete a user's information from the database

    :param current_user: User from the database
    :return: None
    """
    await user_crud.delete_user(current_user)

    return make_logged_out_response("/?accountDeleted=true")


@portal_auth_router.get("/me/deletion-protection")
async def get_disable_deletion_protection_code(
    request: Request, user: User = Depends(get_current_active_user)
):
    """
    Initiate disabling deletion protection for the app. This will send an email.

    :param request: the request from the server
    :param user: the owner of the app.
    :return: HTML for the confirmation form
    """
    vm = VMBase(request)
    await vm.check_for_user()
    code = deletion_protection.generate_dp_code(user, "account")
    try:
        await io_email.send(
            to=user.email,
            subject="Deletion Protection Code",
            text=f"Enter this code to disable deletion protection "
            f"for your user account: {code}. This code will expire in "
            f"{config.OTP_LIFETIME} minutes.",
            from_name="Purple Authentication",
            reply_to=config.WEBMASTER_EMAIL,
        )
    except io_email.EmailError:
        raise HTTPException(status_code=500, detail="Failed to send email")
    return templates.TemplateResponse(
        "dashboard/account_deletion_protection_confirm.html", vm.to_dict()
    )


@portal_auth_router.post("/me/deletion-protection")
async def disable_deletion_protection(
    request: Request,
    user: User = Depends(get_current_active_user),
    code: str = Form(...),
):
    vm = VMBase(request)
    await vm.check_for_user()
    vm.app = await user_crud.disable_deletion_protection(user, code)
    res = Response("", status_code=200)
    res.headers["HX-Trigger"] = htmx.make_show_notification_header(
        res.headers,
        "Deletion Protection Disabled",
        f"You can now delete Your account.",
        "info",
    )
    res.headers["HX-Trigger"] = htmx.make_event_header(res.headers, {"closeModal": {}})
    return res
