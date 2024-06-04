from sqlalchemy.orm import Session
from typing import Optional

from auth.models import User, OtpType
from auth.schemas import Register
from auth.utility.utilis import get_hashed_password

def get_user_by_email(email: str, db: Session) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def get_user_by_user_id(id: int, db: Session) -> Optional[User]:
    return db.query(User).filter(User.id == id).first()

def add_user(user: Register, db: Session) -> Optional[User]:
    db_user = User(**user.dict())
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user_password(user: User, new_password: str, db: Session):
    user.password = get_hashed_password(new_password)
    db.commit()

def create_or_update_otp(user: User, otp: str, type: str, db: Session):
    # Check if there's already an OTPType record for this user and type
    user_otp = db.query(OtpType).filter_by(user_id=user.id, type=type).first()
    
    if user_otp:
        # Update the existing OTP record
        user_otp.otp = otp
    else:
        # Create a new OTP record
        user_otp = OtpType(user_id=user.id, type=type, otp=otp)
        db.add(user_otp)
        
    #commit changes to database  
    db.commit()
    db.refresh(user_otp)

    return user_otp


def get_otp(user: User, type: str, db: Session):
     # Check if there's already an OTPType record for this user and type
    return  db.query(OtpType).filter_by(user_id=user.id, type=type).first()
    
 