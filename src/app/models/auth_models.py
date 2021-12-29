from pydantic import BaseModel, EmailStr, Field as PyField


class AuthRequest(BaseModel):
    email: EmailStr = PyField(..., title="User Email Address")


class ConfirmCode(BaseModel):
    email: EmailStr
    code: str


class VerifyToken(BaseModel):
    idToken: str = PyField(..., title="ID Token")


class RequestRefresh(BaseModel):
    refreshToken: str = PyField(..., title="Refresh Token")
