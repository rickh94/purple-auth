import datetime
from typing import Optional

from jwcrypto import jwk
from odmantic import Model, Field as ODMField
from pydantic import BaseModel, EmailStr

# noinspection PyAbstractClass
from app.config import FERNET


class ClientAppCreate(Model):
    pass


# noinspection PyAbstractClass
class ClientApp(Model):
    name: str = ODMField(..., title="Name of the app")
    app_id: str = ODMField(..., title="App unique id")
    enc_key: Optional[bytes]
    enc_refresh_key: Optional[bytes]
    refresh_token_expire_hours: Optional[int]
    redirect_url: str = ODMField(..., title="Redirect URL")
    failure_redirect_url: Optional[str] = ODMField(
        None,
        title="Failure Redirect URL",
        description="Redirect URL for authentication failures",
    )
    owner: Optional[EmailStr] = ODMField(..., title="Owner of the app")
    quota: int = ODMField(
        500,
        title="Authentication Quota",
        description="How many authentications are remaining for this app",
    )
    low_quota_threshold: int = ODMField(
        10,
        title="Low Quota Notification Threshold",
        description="Threshold to start notifying the administrator that they "
        "are almost out of authentications.",
    )
    low_quota_last_notified: datetime.datetime = ODMField(
        datetime.datetime.fromtimestamp(0),
        title="Date and time of last quota notification",
        description="Stores when the last low quota email was sent to avoid spamming "
        "the administrator",
    )

    def get_key(self) -> jwk.JWK:
        pem = FERNET.decrypt(self.enc_key)
        return jwk.JWK.from_pem(pem)

    def set_key(self, key: jwk.JWK):
        pem = key.export_to_pem(private_key=True, password=None)
        self.enc_key = FERNET.encrypt(pem)

    def get_refresh_key(self):
        if not self.enc_refresh_key:
            return None
        pem = FERNET.decrypt(self.enc_refresh_key)
        return jwk.JWK.from_pem(pem)

    def set_refresh_key(self, key: jwk.JWK):
        pem = key.export_to_pem(private_key=True, password=None)
        self.enc_refresh_key = FERNET.encrypt(pem)


class ClientAppPublic(BaseModel):
    name: str
    app_id: str
    redirect_url: str
