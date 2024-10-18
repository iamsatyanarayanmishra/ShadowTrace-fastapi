from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.schemas import ForgotPasswordRequest, ResetPasswordRequest, UserUpdateSchema, UserLoginSchema, OTPVerifySchema, UserResponse, isSubscribedSchema
from app.models import User, Company
from app.database import get_db
from app.services import get_password_hash, generate_otp, send_email, create_access_token, verify_password
from fastapi import Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

router = APIRouter(prefix="/user", tags=["User"])

# Set up the templates folder for HTML files
templates = Jinja2Templates(directory="templates")

# Mount the static folder for CSS, JS, etc.
router.mount("/static", StaticFiles(directory="static"), name="static")

@router.post("/update-profile/")
def update_profile(profile_data: UserUpdateSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == profile_data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found") 
    # Update user profile
    user.username = profile_data.username
    user.name = profile_data.name
    user.email = profile_data.email
    user.mobile = profile_data.mobile
    # user.dob = profile_data.dob
    user.address = profile_data.address
    user.password = get_password_hash(profile_data.password)

    # Generate otp for email verification
    otp = generate_otp(user.email)
    user.otp = otp
    send_email(user.email, otp)
    db.add(user)
    db.commit() 
    return {"message" : "Profile update successful."}

@router.post("/verify-email/")
def verify_email(otp_data: OTPVerifySchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == otp_data.username).first()

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
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    if not verify_password(user_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid Password")

    if user.first_time_login == 1:
        return {"message": "Update your profile before proceeding"}

    otp = generate_otp(user.email)
    user.otp = otp
    send_email(user.email, otp)
    db.commit()
    # access_token = create_access_token(data={"sub": user.username})

    return {"message" : "Kindly Update Your Profile "}

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


@router.post("/verify-subscription/")
def verify_subscription(Subscription_Data: isSubscribedSchema, db: Session = Depends(get_db)):
    # Fetch the user by username
    user = db.query(User).filter(User.username == Subscription_Data.username).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Fetch the company the user is associated with
    company = db.query(Company).filter(Company.id == user.company_id).first()

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    if Subscription_Data.subscribtionModel == "OSINT":
        is_osint_subscribed = company.is_osint_subscribed
        return {"is_osint_subscribed": is_osint_subscribed}
    
    if Subscription_Data.subscribtionModel == "E-Discovery":
        is_ediscovery_subscribed = company.is_eDiscovery_subscribed
        return {"is_ediscovery_subscribed": is_ediscovery_subscribed}


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