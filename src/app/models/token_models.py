import datetime
from typing import Optional

import mongox
from pydantic import EmailStr, BaseModel, Field as PyField


# noinspection PyAbstractClass
from app.database import db


class RefreshToken(mongox.Model):
    """
    The stored component of a refresh token. There is a stored hash of part
    of a refresh token so that they can be invalidated (unlike normal jwts).

    This will store the needed information for validating refresh tokens until they
    expired, at which point mongo will automatically delete them based on the
    "expires" index.
    """

    app_id: str
    email: EmailStr
    hash: str
    expires: datetime.datetime
    uid: str

    class Meta:
        collection = db.get_collection("refresh_tokens")
        indexes = [
            mongox.Index("app_id"),
            mongox.Index("email"),
            mongox.Index("expires", expireAfterSeconds=0),
        ]


class VerifiedTokenResponse(BaseModel):
    headers: dict
    claims: dict


class IssueToken(BaseModel):
    idToken: str = PyField(..., title="ID Token")
    refreshToken: Optional[str] = PyField(
        None,
        title="Refresh Token",
    )
