from typing import Dict

from odmantic import Model, Field
from pydantic import BaseModel


class ClientApp(Model):
    name: str = Field(..., title="Name of the app")
    app_id: str = Field(..., title="app unique id")
    key: Dict[str, str]
    redirect_url: str = Field(..., title="Redirect URL")


class VerifiedTokenResponse(BaseModel):
    headers: dict
    claims: dict
