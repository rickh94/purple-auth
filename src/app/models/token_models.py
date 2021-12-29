import datetime
from typing import Optional

from odmantic import Model
from pydantic import EmailStr, BaseModel, Field as PyField


# noinspection PyAbstractClass
class RefreshToken(Model):
    app_id: str
    email: EmailStr
    hash: str
    expires: datetime.datetime
    uid: str


class VerifiedTokenResponse(BaseModel):
    headers: dict
    claims: dict


class IssueToken(BaseModel):
    idToken: str = PyField(..., title="ID Token")
    refreshToken: Optional[str] = PyField(
        None,
        title="Refresh Token",
    )
