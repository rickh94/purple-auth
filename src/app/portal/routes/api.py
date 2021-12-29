from fastapi import APIRouter

portal_api_router = APIRouter()


@portal_api_router.get("/apps")
async def get_my_apps():
    # TODO: restrict to user
    pass


@portal_api_router.post("/apps/create")
async def create_app():
    pass


@portal_api_router.post("/apps/{app_id}/update")
async def update_app():
    pass
