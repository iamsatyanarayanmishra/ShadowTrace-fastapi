from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserUpdateSchema(BaseModel):
    username : str
    name: str
    email: EmailStr
    mobile: Optional[str]
    dob: Optional[datetime]
    address: Optional[str]
    password: str

class UserCreationSchema(BaseModel):
    company_name : str
    company_address : str

class UserLoginSchema(BaseModel):
    username: str
    password: str

class OTPVerifySchema(BaseModel):
    otp: str

class UserResponse(BaseModel):
    username: str
    email_verified: bool
    first_time_login: bool

    class Config:
        from_attributes = True  # Changed from 'orm_mode' to 'from_attributes'

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    otp: str
    new_password: str