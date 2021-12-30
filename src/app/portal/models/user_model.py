from typing import Optional

import mongox
from pydantic import EmailStr, BaseModel


# noinspection PyAbstractClass
from app.database import db


class User(mongox.Model):
    email: EmailStr = mongox.Field(..., title="User Email Address", unique=True)
    name: Optional[str] = mongox.Field(None, title="User Name")
    disabled: bool = mongox.Field(False, title="Disabled")

    class Meta:
        collection = db.get_collection("portal_users")
        indexes = [mongox.Index("email", unique=True)]


class UserPublic(BaseModel):
    email: str
    name: Optional[str] = None
