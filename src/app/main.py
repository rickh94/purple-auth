from fastapi import FastAPI, Request

from app import config
from app.routes.otp import otp_router
from app.routes.token import token_router

app = FastAPI(title="Auth Service", version=config.VERSION)


# @app.middleware("http")
# async def check_client_app(request: Request, call_next):
#     print(request)
#     return await call_next(request)
#

app.include_router(otp_router, prefix="/otp", tags=["otp"])

app.include_router(token_router, prefix="/token", tags=["token"])
