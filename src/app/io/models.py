from typing import Dict, Optional

from odmantic import Model, Field as ODMField
from pydantic import BaseModel, Field as PyField


# noinspection PyAbstractClass
class ClientApp(Model):
    name: str = ODMField(..., title="Name of the app")
    app_id: str = ODMField(..., title="app unique id")
    key: Dict[str, str]
    redirect_url: str = ODMField(..., title="Redirect URL")


class ClientAppPublic(Model):
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
