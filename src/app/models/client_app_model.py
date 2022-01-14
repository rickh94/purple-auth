import datetime
from typing import Optional

import mongox
from jwcrypto import jwk
from pydantic import BaseModel, EmailStr

# noinspection PyAbstractClass
from app.config import FERNET
from app.database import db


# Consider moving quota information into a sub-document
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
    unlimited: bool = mongox.Field(
        False,
        title="Unlimited tier app",
        description="If enabled, app quota will be ignored. This can only be set "
        "manually the an administrator.",
    )
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
    deletion_protection: bool = mongox.Field(
        True,
        title="Deletion Protection",
        description="If enabled, the app cannot be deleted",
    )
    created: datetime.datetime = mongox.Field(
        default_factory=datetime.datetime.now,
        title="Date and time of creation.",
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

    @property
    def refresh_enabled(self) -> bool:
        return self.enc_refresh_key is not None

    def change_refresh(self, enabled: bool):
        # If the refresh state doesn't change, do nothing. (i.e. is already enabled
        # or already disabled)
        if self.refresh_enabled == enabled:
            return
        if enabled:
            self.set_refresh_key(jwk.JWK.generate(kty="EC", size=4096))
        elif not enabled:
            self.enc_refresh_key = None


class ClientAppPublic(BaseModel):
    name: str
    app_id: str
    redirect_url: str
