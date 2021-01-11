from fastapi import FastAPI, Request

from app import config
from app.routes.client_app import client_app_router
from app.routes.magic import magic_router
from app.routes.otp import otp_router
from app.routes.token import token_router

app = FastAPI(title="Auth Service", version=config.VERSION)


app.include_router(otp_router, prefix="/otp", tags=["otp"])
app.include_router(token_router, prefix="/token", tags=["token"])
app.include_router(client_app_router, prefix="/app", tags=["app"])
app.include_router(magic_router, prefix="/magic", tags=["magic"])
