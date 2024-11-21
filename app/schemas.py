from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime
from fastapi import File, UploadFile


class UserCreationSchema(BaseModel):
    company_name : str
    company_address : str
    is_osint_subscribed : bool
    is_eDiscovery_subscribed : bool


class UserLoginSchema(BaseModel):
    username: str
    password: str


class UserUpdateSchema(BaseModel):
    name: str
    email: EmailStr
    mobile: Optional[str]
    address: Optional[str]
    password: Optional[str]

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

class isSubscribedSchema(BaseModel):
    subscribtionModel: str

class UserSchema(BaseModel):
    username: str
    email: str
    mobile: Optional[str] = None
    image_path: Optional[str] = None  # Add this field for profile picture URL

    class Config:
        orm_mode = True
