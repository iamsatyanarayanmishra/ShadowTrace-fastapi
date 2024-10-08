from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.schemas import ForgotPasswordRequest, ResetPasswordRequest, UserUpdateSchema, UserLoginSchema, OTPVerifySchema, UserResponse
from app.models import User
from app.database import get_db
from app.services import get_password_hash, generate_otp, send_email, create_access_token

router = APIRouter(prefix="/user", tags=["User"])

@router.post("/update-profile/", response_model=UserResponse)
def update_profile(profile_data: UserUpdateSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == profile_data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found") 
    # Update user profile
    user.name = profile_data.name
    user.email = profile_data.email
    user.mobile = profile_data.mobile
    user.dob = profile_data.dob
    user.address = profile_data.address
    user.password = get_password_hash(profile_data.password)

    # Generate otp for email verification
    otp = generate_otp(user.email)
    user.otp = otp
    send_email(user.email, otp)
    user.first_time_login = 0

    db.add(user)
    db.commit()
    UserResponse = {
        "username" : profile_data.username,
        "email_verified" : user.email_verified,
        "first_time_login" : user.first_time_login
    }
    return UserResponse

@router.post("/verify-email/")
def verify_email(user_name: str, otp_data: OTPVerifySchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_name).first()

    if not user or user.otp != otp_data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP or user not found")

    user.email_verified = True
    user.first_time_login = False
    user.otp = None  # Clear OTP after verification
    db.commit()

    return {"message": "Email verified successfully"}

@router.post("/login/")
def login(user_data: UserLoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_data.username).first()

    if user.username != user_data.username:
        return {"message": "Invalid Username"} 

    if user.first_time_login == 1:
        return {"message": "Update your profile"}

    # Generate OTP for two-step verification
    otp = generate_otp(user.email)
    user.otp = otp
    send_email(user.email, otp)
    access_token = create_access_token(data={"sub": user.username})

    db.commit()
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/verify-login/")
def verify_login(user_name: str, otp_data: OTPVerifySchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_name).first()

    if not user or user.otp != otp_data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Generate JWT for session
    access_token = create_access_token(data={"sub": user.username})
    user.otp = None  # Clear OTP
    db.commit()

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/forgot-password/")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate OTP or token
    otp = generate_otp(user.email)  # Generating a simple OTP
    user.otp = otp
    user.otp_expiration = datetime.utcnow() + timedelta(minutes=10)  # OTP valid for 10 mins
    db.commit()
    
    # Send email with OTP
    subject = "Password Reset OTP"
    body = f"Your OTP for resetting your password is {otp}. It will expire in 10 minutes."
    send_email(user.email, otp)

    return {"message": "OTP sent to your email"}

@router.post("/reset-password/")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.otp == request.otp).first()

    if not user or user.otp_expiration < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Hash and set the new password
    hashed_password = get_password_hash(request.new_password)
    user.password = hashed_password
    user.otp = None  # Clear OTP
    user.otp_expiration = None  # Clear OTP expiration
    db.commit()

    return {"message": "Password has been reset successfully"}

    
