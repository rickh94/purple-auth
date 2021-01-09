import datetime
from typing import Dict, Optional

from odmantic import Model, Field as ODMField
from pydantic import BaseModel, Field as PyField, EmailStr


# noinspection PyAbstractClass
class ClientApp(Model):
    name: str = ODMField(..., title="Name of the app")
    app_id: str = ODMField(..., title="app unique id")
    key: Dict[str, str]
    refresh_key: Optional[Dict[str, str]]
    refresh_token_expire_hours: Optional[int]
    redirect_url: str = ODMField(..., title="Redirect URL")


# noinspection PyAbstractClass
class RefreshToken(Model):
    app_id: str
    email: EmailStr
    hash: str
    expires: datetime.datetime
    uid: str


class ClientAppPublic(BaseModel):
    name: str
    app_id: str
    redirect_url: str


class VerifiedTokenResponse(BaseModel):
    headers: dict
    claims: dict


class IssueToken(BaseModel):
    idToken: str = PyField(..., title="ID Token")
    refreshToken: Optional[str] = PyField(
        None,
        title="Refresh Token",
    )


class AuthRequest(BaseModel):
    email: EmailStr = PyField(..., title="User Email Address")


class ConfirmCode(BaseModel):
    email: EmailStr
    code: str
