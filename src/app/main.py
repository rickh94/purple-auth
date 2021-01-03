from fastapi import FastAPI

from app import config
from routes.otp import otp_router

app = FastAPI(title="Auth Service", version=config.VERSION)

app.include_router(otp_router, prefix="/otp", tags=["otp"])
