import logging

from fastapi import APIRouter, Query
from starlette.requests import Request

from app.portal.security import try_refresh
from app.portal.services.auth import (
    refresh_or_redirect_to_login,
    make_authenticated_response,
    make_redirect_response,
)
from app.portal.services.templates import templates
from app.portal.viewmodels.base_vm import VMBase
from app.portal.viewmodels.dashboard_vm import DashboardVM
from app.portal.viewmodels.howitworks_vm import HowItWorksVM
from app.portal.viewmodels.index_vm import IndexVM
from app.portal.viewmodels.login_vm import LoginVM
from app.portal.viewmodels.seo_vm import SeoVM
from app.portal.viewmodels.techdocs_vm import TechDocsVM

portal_router = APIRouter()


@portal_router.get("/")
async def index(request: Request):
    vm = IndexVM(request)
    await vm.check_for_user()
    return templates.TemplateResponse("index.html", vm.to_dict())


@portal_router.get("/how-it-works")
async def how_it_works(request: Request):
    vm = HowItWorksVM(request)
    await vm.check_for_user()
    return templates.TemplateResponse("how-it-works.html", vm.to_dict())


@portal_router.get("/walkthrough")
async def tech_docs(request: Request):
    vm = TechDocsVM(request)
    await vm.check_for_user()
    return templates.TemplateResponse("walkthrough.html", vm.to_dict())


@portal_router.get("/dashboard")
async def dashboard(request: Request):
    vm = DashboardVM(request)
    if not await vm.check_for_user():
        return refresh_or_redirect_to_login("/dashboard")
    await vm.get_user_apps()
    return templates.TemplateResponse("dashboard/dashboard.html", vm.to_dict())


@portal_router.get("/tech-docs")
async def tech_docs(request: Request):
    vm = TechDocsVM(request)
    return templates.TemplateResponse("walkthrough.html", vm.to_dict())


@portal_router.get("/login/confirm")
async def confirm_login(request: Request, email: str = Query(None)):
    vm = LoginVM(request, user_email=email)
    if await vm.check_for_user():
        return make_redirect_response("/dashboard")
    return templates.TemplateResponse("login/confirm_code.html", vm.to_dict())


@portal_router.get("/login/magic-message")
async def magic_message(request: Request):
    vm = LoginVM(request)
    if await vm.check_for_user():
        return make_redirect_response("/dashboard")
    return templates.TemplateResponse("login/magic_message.html", vm.to_dict())


@portal_router.get("/login/magic-failed")
async def magic_failed_message(request: Request):
    vm = LoginVM(request)
    if await vm.check_for_user():
        return make_redirect_response("/dashboard")
    return templates.TemplateResponse("login/magic_failed.html", vm.to_dict())


@portal_router.get("/login")
async def start_login(
    request: Request,
    next_url: str = Query("/dashboard", alias="next"),
):
    vm = LoginVM(request)
    if await vm.check_for_user():
        return make_redirect_response("/dashboard")
    if id_token := await try_refresh(request):
        logging.debug("successfully refreshed")
        return make_authenticated_response(
            f"{next_url}?sessionRefreshed=true", id_token
        )
    return templates.TemplateResponse("login/login.html", vm.to_dict())


@portal_router.get("/sitemap.xml")
async def sitemap(request: Request):
    vm = SeoVM(request)
    return templates.TemplateResponse(
        "sitemap.xml", vm.to_dict(), media_type="text/xml"
    )


@portal_router.get("/robots.txt")
async def robots_txt(request: Request):
    vm = SeoVM(request)
    return templates.TemplateResponse(
        "robots.txt", vm.to_dict(), media_type="text/plain"
    )
