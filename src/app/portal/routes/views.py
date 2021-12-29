from pathlib import Path

from fastapi import APIRouter
from starlette.requests import Request
from starlette.templating import Jinja2Templates

from app.portal.viewmodels.dashboard_vm import DashboardVM
from app.portal.viewmodels.howitworks_vm import HowItWorksVM
from app.portal.viewmodels.index_vm import IndexVM
from app.portal.viewmodels.techdocs_vm import TechDocsVM

portal_router = APIRouter()

template_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(template_dir.absolute()))


@portal_router.get("/")
async def index(request: Request):
    vm = IndexVM(request)
    return templates.TemplateResponse("index.html", vm.to_dict())


@portal_router.get("/how-it-works")
async def how_it_works(request: Request):
    vm = HowItWorksVM(request)
    return templates.TemplateResponse("how-it-works.html", vm.to_dict())


@portal_router.get("/dashboard")
async def dashboard(request: Request):
    vm = DashboardVM(request)
    return templates.TemplateResponse("dashboard.html", vm.to_dict())


@portal_router.get("/tech-docs")
async def tech_docs(request: Request):
    vm = TechDocsVM(request)
    return templates.TemplateResponse("tech-docs.html", vm.to_dict())


@portal_router.get("/login/confirm")
async def confirm_login(request: Request):
    pass


@portal_router.get("/login/magic-message")
async def magic_message(request: Request):
    pass
