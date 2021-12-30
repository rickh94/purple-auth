import datetime
from typing import Optional

import mongox
from jwcrypto import jwk
from pydantic import BaseModel, EmailStr

# noinspection PyAbstractClass
from app.config import FERNET
from app.database import db


class ClientAppCreate(BaseModel):
    pass


# noinspection PyAbstractClass
class ClientApp(mongox.Model):
    name: str = mongox.Field(..., title="Name of the app")
    app_id: str = mongox.Field(..., title="App unique id")
    enc_key: Optional[bytes]
    enc_refresh_key: Optional[bytes]
    refresh_token_expire_hours: Optional[int]
    redirect_url: str = mongox.Field(..., title="Redirect URL")
    failure_redirect_url: Optional[str] = mongox.Field(
        None,
        title="Failure Redirect URL",
        description="Redirect URL for authentication failures",
    )
    owner: Optional[EmailStr] = mongox.Field(..., title="Owner of the app")
    quota: int = mongox.Field(
        500,
        title="Authentication Quota",
        description="How many authentications are remaining for this app",
    )
    low_quota_threshold: int = mongox.Field(
        10,
        title="Low Quota Notification Threshold",
        description="Threshold to start notifying the administrator that they "
        "are almost out of authentications.",
    )
    low_quota_last_notified: datetime.datetime = mongox.Field(
        datetime.datetime.fromtimestamp(0),
        title="Date and time of last quota notification",
        description="Stores when the last low quota email was sent to avoid spamming "
        "the administrator",
    )

    class Meta:
        collection = db.get_collection("client_apps")
        indexes = [mongox.Index("app_id", unique=True), mongox.Index("owner")]

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
