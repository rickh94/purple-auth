import secrets

import ujson
from fastapi import APIRouter, Form, Depends, Response, Header, HTTPException
from starlette.requests import Request

from app import config
from app.portal.crud import clientapp_crud
from app.portal.models.user_model import User
from app.portal.services import htmx, deletion_protection
from app.portal.services.auth import refresh_or_redirect_to_login
from app.portal.services.templates import templates
from app.portal.security import get_current_active_user
from app.portal.viewmodels.dashboard_vm import DashboardVM
from app.portal.viewmodels.singleapp_vm import SingleAppVM
from app.io import email as io_email

portal_api_router = APIRouter()


# CREATE


@portal_api_router.get("/apps/create")
async def dashboard_form_create_app(request: Request):
    vm = DashboardVM(request)
    if not await vm.check_for_user():
        return refresh_or_redirect_to_login("/dashboard")
    res = templates.TemplateResponse("dashboard/create_app_form.html", vm.to_dict())
    res.headers["HX-Trigger-After-Swap"] = "openModal"
    return res


@portal_api_router.post("/apps/create")
async def create_app(
    request: Request,
    app_name: str = Form(...),
    redirect_url: str = Form(...),
    failure_redirect_url: str = Form(...),
    refresh: bool = Form(False),
    refresh_token_expire_hours: int = Form(24),
    user: User = Depends(get_current_active_user),
):
    """
    Create a new app to authenticate against.

    :param request: request from the server
    :param app_name: The name of the app
    :param redirect_url: The url to redirect to after a successful magic link
    authentication.
    :param failure_redirect_url: The url to redirect to after a failed magic link
    authentication attempt.
    :param refresh: Whether to enable refresh on the app
    :param refresh_token_expire_hours: How long refresh tokens are valid for.
    :param user: The user creating the app. This route requires authentication.
    :return: HTML for the app in the list and events to display the full app.
    """
    api_key = secrets.token_urlsafe()
    new_app = await clientapp_crud.create_client_app(
        app_name=app_name,
        owner=user.email,
        redirect_url=redirect_url,
        refresh=refresh,
        refresh_token_expire_hours=refresh_token_expire_hours,
        failure_redirect_url=failure_redirect_url,
        api_key=api_key,
    )
    vm = SingleAppVM(request, new_app)
    res = templates.TemplateResponse(
        "dashboard/single_app.html",
        vm.to_dict(),
        headers={"HX-Trigger": '{"closeModal": "{}"}'},
        status_code=201,
    )
    res.headers["HX-Trigger"] = htmx.make_show_notification_header(
        res.headers,
        "App Created",
        f"Your app {new_app.name} has been created!",
        "success",
    )
    res.headers["HX-Trigger"] = htmx.make_event_header(
        res.headers, {"appCreated": "{}"}
    )
    res.headers["HX-Trigger-After-Settle"] = ujson.dumps(
        {
            "showApp": new_app.app_id,
            "showApiKey": api_key,
        }
    )
    return res


# READ


@portal_api_router.get("/apps/{app_id}")
async def get_app_display(
    request: Request, app_id: str, _user: User = Depends(get_current_active_user)
):
    """
    Get the HTML for the app display.

    :param request: the request from the server
    :param app_id: the unique id for the app
    :param _user: the user who owns the app. This route requires authentication.
    :return: HTML for the app display modal with an event to open the modal.
    """
    vm = SingleAppVM(request)
    await vm.get_app(app_id)
    return templates.TemplateResponse(
        "dashboard/app_display.html",
        vm.to_dict(),
        headers={"HX-Trigger-After-Settle": "openModal"},
    )


# UPDATE


@portal_api_router.put("/apps/{app_id}")
async def update_app(
    request: Request,
    app_id: str,
    app_name: str = Form(...),
    redirect_url: str = Form(...),
    failure_redirect_url: str = Form(...),
    refresh_enabled: bool = Form(...),
    refresh_token_expire_hours: int = Form(24),
    low_quota_threshold: int = Form(10),
    user: User = Depends(get_current_active_user),
):
    """
    Update an app.

    :param request: the request from the server
    :param app_id: the unique id for the app to updated
    :param app_name: the new name for the app
    :param redirect_url: updated redirect url (see create_app)
    :param failure_redirect_url:  updated failure redirect url (see create_app)
    :param refresh_enabled: whether to enable refresh on the app
    :param refresh_token_expire_hours: how long refresh tokens are valid for.
    :param low_quota_threshold: how many authentications should be left before the
    app owner is notified that they are running out
    :param user: the owner of the app. This route requires authentication.
    :return: HTML to replace the app in the list and an event to display the app
    """
    updated_app = await clientapp_crud.update_client_app(
        app_id,
        user,
        app_name,
        redirect_url,
        refresh_enabled,
        refresh_token_expire_hours,
        failure_redirect_url,
        low_quota_threshold,
    )
    vm = SingleAppVM(request, updated_app)
    res = templates.TemplateResponse(
        "dashboard/single_app.html",
        vm.to_dict(),
    )
    res.headers["HX-Trigger"] = htmx.make_event_header(res.headers, {"closeModal": {}})
    res.headers["HX-Trigger"] = htmx.make_show_notification_header(
        res.headers,
        "App Updated",
        f"Your app {updated_app.name} has been updated!",
        "success",
    )
    res.headers["HX-Trigger-After-Settle"] = ujson.dumps(
        {"showApp": updated_app.app_id}
    )
    return res


@portal_api_router.get("/apps/{app_id}/rotate-keys")
async def rotate_app_keys_form(
    request: Request, app_id: str, _user: User = Depends(get_current_active_user)
):
    """
    Get the form to rotate app encryption keys.

    :param request: request from the server
    :param app_id: the unique id of the app to rotate keys for
    :param _user: the user who owns the app. this route requires authentication

    :return: HTML of the appropriate form
    """
    vm = SingleAppVM(request)
    await vm.get_app(app_id)
    return templates.TemplateResponse(
        "dashboard/app_change_keys.html",
        vm.to_dict(),
    )


@portal_api_router.post("/apps/{app_id}/rotate-keys")
async def rotate_app_keys(app_id: str, user: User = Depends(get_current_active_user)):
    """
    Rotate app encryption keys.
    :param app_id: the app to rotate keys for
    :param user: the owner of the app. This route requires authentication.
    :return: empty response with headers to close the modal and show a notification
    """
    await clientapp_crud.rotate_app_keys(app_id, user)
    res = Response(
        content="", status_code=200, headers={"HX-Trigger": '{"closeModal": "{}"}'}
    )
    res.headers["HX-Trigger"] = htmx.make_show_notification_header(
        res.headers,
        "App Keys Changed",
        "Your app encryption keys have been changed. All users will need to "
        "re-authenticate and you will need to download new public keys anywhere they "
        "may have been cached",
        "success",
    )
    return res


# TODO: add confirmation dialog for changing the api key


@portal_api_router.get("/apps/{app_id}/reset-api-key")
async def reset_api_key_form(
    request: Request, app_id: str, user: User = Depends(get_current_active_user)
):
    """
    Reset app api key.

    :param app_id:
    :param user:
    :return:
    """
    app = await clientapp_crud.get_client_app(app_id, user)
    return templates.TemplateResponse(
        "dashboard/confirm_reset_api_key.html", {"request": request, "app": app}
    )


@portal_api_router.post("/apps/{app_id}/reset-api-key")
async def reset_api_key(
    app_id: str, user: User = Depends(get_current_active_user), name: str = Form(...)
):
    """
    Get the form to confirm resetting the app api keys
    :param app_id: the id of the app
    :param user: current user
    :param name: The user-typed name of the app for confirmation
    :return:
    """
    app = await clientapp_crud.get_client_app(app_id, user)
    if app.name != name:
        raise HTTPException(status_code=400, detail="Incorrect App name.")
        # return templates.TemplateResponse(
        #     "dashboard/confirm_reset_api_key.html",
        #     {"error": "Incorrect App name.", "app": app, "request": request},
        # )
    new_api_key = secrets.token_urlsafe()
    await clientapp_crud.update_api_key(app, new_api_key)
    res = Response(
        content="", status_code=200, headers={"HX-Trigger": '{"closeModal": "{}"}'}
    )
    res.headers["HX-Trigger-After-Settle"] = ujson.dumps({"showApiKey": new_api_key})
    return res


# DELETE


@portal_api_router.get("/apps/{app_id}/delete")
async def delete_app_form(
    request: Request, app_id: str, _user: User = Depends(get_current_active_user)
):
    """
    Get HTML to either confirm deletion of the app or begin disabling deletion
    protection.
    :param request: the request from the server
    :param app_id: the unique id for the app to delete
    :param _user: the user who owns the app, this route requires authentication
    :return: HTML for the appropriate form
    """
    vm = SingleAppVM(request)
    await vm.get_app(app_id)
    if vm.app.deletion_protection:
        return templates.TemplateResponse(
            "dashboard/app_deletion_protection_warning.html", vm.to_dict()
        )
    return templates.TemplateResponse(
        "dashboard/app_delete.html",
        vm.to_dict(),
        headers={"HX-Trigger-After-Settle": "openModal"},
    )


@portal_api_router.delete("/apps/0")
async def cant_delete_portal():
    """Hard protection against accidentally deleting the portal"""
    raise HTTPException(status_code=400, detail="Cannot delete the portal app.")


@portal_api_router.delete("/apps/{app_id}")
async def delete_app(
    app_id: str,
    user: User = Depends(get_current_active_user),
    hx_target: str = Header(...),
):
    """
    Delete an app and all associated refresh tokens.
    :param app_id: the unique id of the app to delete
    :param user: the owner of the app, this route requires authentication
    :param hx_target: the html element id of the app to remove it from the dom on
    the response
    :return: empty response with headers to close the modal, remove the app from the
    list and show a notification
    """
    # This should be unreachable...but just in case.
    if app_id == "0":
        raise HTTPException(status_code=400, detail="Cannot delete the portal app.")

    name = await clientapp_crud.delete_app(app_id, user)
    res = Response(
        content="", status_code=204, headers={"HX-Trigger": '{"closeModal": "{}"}'}
    )
    res.headers["HX-Trigger"] = htmx.make_show_notification_header(
        res.headers, "App Deleted", f"Your app {name} has been deleted!", "success"
    )
    res.headers["HX-Trigger"] = htmx.make_event_header(
        res.headers, {"removeApp": hx_target}
    )
    return res


@portal_api_router.get("/apps/{app_id}/deletion-protection")
async def get_disable_deletion_protection_code(
    request: Request, app_id: str, user: User = Depends(get_current_active_user)
):
    """
    Initiate disabling deletion protection for the app. This will send an email.

    :param request: the request from the server
    :param app_id: the unique id of the app.
    :param user: the owner of the app.
    :return:
    """
    vm = SingleAppVM(request)
    await vm.get_app(app_id)
    code = deletion_protection.generate_dp_code(user, vm.app.app_id)
    try:
        await io_email.send(
            to=user.email,
            subject="Deletion Protection Code",
            text=f"Enter this code to disable deletion protection "
            f"for {vm.app.name}: {code}. This code will expire in "
            f"{config.OTP_LIFETIME} minutes.",
            from_name="Purple Authentication",
            reply_to=config.WEBMASTER_EMAIL,
        )
    except io_email.EmailError:
        raise HTTPException(status_code=500, detail="Failed to send email")
    return templates.TemplateResponse(
        "dashboard/app_deletion_protection_confirm.html", vm.to_dict()
    )


@portal_api_router.post("/apps/{app_id}/deletion-protection")
async def disable_deletion_protection(
    request: Request,
    app_id: str,
    user: User = Depends(get_current_active_user),
    code: str = Form(...),
):
    vm = SingleAppVM(request)
    await vm.check_for_user()
    vm.app = await clientapp_crud.disable_deletion_protection(app_id, user, code)
    res = templates.TemplateResponse("dashboard/app_display.html", vm.to_dict())
    res.headers["HX-Trigger-After-Settle"] = ujson.dumps(
        {"flashAppSection": "deletion_protection"}
    )
    return res


@portal_api_router.post("/apps/{app_id}/deletion-protection/enable")
async def enable_deletion_protection(
    request: Request, app_id: str, user: User = Depends(get_current_active_user)
):
    vm = SingleAppVM(request)
    await vm.check_for_user()
    vm.app = await clientapp_crud.enable_deletion_protection(app_id, user)
    res = templates.TemplateResponse(
        "dashboard/deletion_protection_display.html", vm.to_dict()
    )
    res.headers["HX-Trigger-After-Settle"] = ujson.dumps(
        {"flashAppSection": "deletion_protection"}
    )
    return res
