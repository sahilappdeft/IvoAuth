from datetime import datetime, timedelta
from typing import Optional

from pydantic import BaseModel,  EmailStr, constr


class UserResponse(BaseModel):
    id: int
    created: datetime
    updated: datetime
    email: str
    first_name: str
    last_name: str
    email_verified: bool
    otp: Optional[str] = None

    class Config:
        from_attributes = True


class Register(BaseModel):
    first_name: str
    last_name: str
    password: constr(min_length=7)
    email: EmailStr
    email_verified: Optional[bool] = False


class Login(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class Refresh(BaseModel):
    access_token: str
    token_type: str


class VerifyEmail(BaseModel):
    email: EmailStr
    otp: str


class OtpRequest(BaseModel):
    email: EmailStr
    type: str


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    password: str
    confirm_password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str
