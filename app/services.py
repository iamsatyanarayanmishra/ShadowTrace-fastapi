from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import HTTPException
from app.database import get_db
from app.models import User
from sqlalchemy.orm import Session
from fastapi import Depends

# Hashing passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Helper to hash passwords
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Helper function to create access tokens
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to generate OTP
def generate_otp(email: str, db: Session = Depends(get_db)):
    otp = str(random.randint(100000, 999999))
    return otp

def send_email(email: str, otp: str):
    # Email configuration
    sender_email = "iamsatyanarayanmishra@gmail.com"  # Replace with your email
    sender_password = "meil pcfa plsc sdjd"    # Use your Google account password or App Password
    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as server:  # Use Gmail's SMTP server
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, sender_password)  # Login to your email account
            server.send_message(msg)  # Send the email

        print(f"Sending OTP {otp} to email {email}")

    except Exception as e:
        print(f"Failed to send email: {e}")
        raise HTTPException(status_code=500, detail="Email sending failed")