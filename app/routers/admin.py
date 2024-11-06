import random
import string
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.models import Company, User
from app.database import get_db
from app.services import get_password_hash
from app.schemas import UserCreationSchema
router = APIRouter(prefix="/admin", tags=["Admin"])


@router.post("/create-user/")
def create_user(profile_data: UserCreationSchema, db: Session = Depends(get_db)):
    username = generate_user_id()
    password = generate_random_password()
    is_osint_subscribed = profile_data.is_osint_subscribed
    is_eDiscovery_subscribed = profile_data.is_eDiscovery_subscribed
    hashed_password = get_password_hash(password)

    company = db.query(Company).filter(Company.company_name == profile_data.company_name).first()
    if not company:
        new_company = Company(
            company_name=profile_data.company_name,
            company_address=profile_data.company_address,
            is_osint_subscribed = is_osint_subscribed,
            is_eDiscovery_subscribed = is_eDiscovery_subscribed
        )
        db.add(new_company)
        db.flush()  # Ensure the new company is created before assigning it to the user
        company = new_company  # Now we can use the newly created company

    new_user = User(
        username=username,
        company_id=company.id,  
        password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    print("Your username : %s and password: %s" % (username, password))
    return {"username": username, "password": password}



def generate_user_id():
    prefix = "S"
    middle_letter = "T"
    first_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=2))
    second_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=2))    
    user_id = f"{prefix}{first_part}{middle_letter}{second_part}"
    return user_id



def generate_random_password(length=8):
    """Generates a random password."""
    letters = string.ascii_letters
    digits = string.digits
    all_chars = letters + digits
    return ''.join(random.choice(all_chars) for _ in range(length))
