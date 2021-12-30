import datetime
from typing import Optional

import mongox
from pydantic import EmailStr, BaseModel, Field as PyField


# noinspection PyAbstractClass
from app.database import db


class RefreshToken(mongox.Model):
    app_id: str
    email: EmailStr
    hash: str
    expires: datetime.datetime
    uid: str

    class Meta:
        collection = db.get_collection("refresh_tokens")
        indexes = [mongox.Index("app_id"), mongox.Index("email")]


class VerifiedTokenResponse(BaseModel):
    headers: dict
    claims: dict


class IssueToken(BaseModel):
    idToken: str = PyField(..., title="ID Token")
    refreshToken: Optional[str] = PyField(
        None,
        title="Refresh Token",
    )
