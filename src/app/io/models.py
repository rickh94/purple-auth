import datetime
from typing import Dict, Optional

from jwcrypto import jwk
from odmantic import Model, Field as ODMField
from pydantic import BaseModel, Field as PyField, EmailStr


# noinspection PyAbstractClass
from app.config import FERNET


class ClientApp(Model):
    name: str = ODMField(..., title="Name of the app")
    app_id: str = ODMField(..., title="app unique id")
    enc_key: Optional[bytes]
    enc_refresh_key: Optional[bytes]
    refresh_token_expire_hours: Optional[int]
    redirect_url: str = ODMField(..., title="Redirect URL")

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


class VerifyToken(BaseModel):
    idToken: str = PyField(..., title="ID Token")
