from typing import Optional

from odmantic import Model, Field as ODMField

from pydantic import EmailStr, BaseModel


# noinspection PyAbstractClass
class User(Model):
    email: EmailStr = ODMField(..., title="User Email Address", unique=True)
    name: Optional[str] = ODMField(None, title="User Name")
    disabled: bool = ODMField(False, title="Disabled")


class UserPublic(BaseModel):
    email: str
    name: Optional[str] = None
