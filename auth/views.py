import ast

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from jose import jwt, JWTError

from fastapi import Depends, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


from auth.database import get_db
from auth.schemas import (Register, UserResponse, Token, Login, VerifyEmail, OtpRequest,
                           ResetPasswordRequest, ChangePasswordRequest
                        )
from auth.services import get_user_by_email, add_user, update_user_password, create_or_update_otp, get_otp, get_user_by_user_id
from auth.utility.jwt import create_access_token, create_refresh_token, JWT_SECRET_KEY
from auth.utility.utilis import generateOTP, verify_password
from .models import User, OtpType

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        # Decode the JWT token and extract the payload
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        
        # Extract the email from the payload
        user_data = payload.get("sub")
        user_data =  ast.literal_eval(user_data)# Convert string to dictionary
        
        # Check if email exists in the payload
        if user_data.get('email') is None:
            # If email is missing, raise HTTP 401 Unauthorized
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
        
        # Query the database to get the user by email
        user = get_user_by_email(user_data.get('email'), db)
        
        # Check if user exists
        if user is None:
            # If user does not exist, raise HTTP 401 Unauthorized
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        
        # Return the user if everything is valid
        return user
    except JWTError:
        # If there's an error decoding the token, raise HTTP 401 Unauthorized
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")


@router.post("/token")
async def token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # get user from the database
    user = get_user_by_email(form_data.username, db)
    
    if not user.email_verified:
        # Check if user email_verified.
        raise HTTPException(status_code=401, detail="Please verify your email first")
    
    if not user or not verify_password(form_data.password, user.password):
        # Check if user exists or if the provided password is incorrect
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    access_token = create_access_token(subject={"email":user.email, "id": user.id})
    refresh_token = create_refresh_token(subject={"email":user.email, "id": user.id})

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}



@router.post('/signup', summary="Create new user", response_model=UserResponse)
async def create_user(register_data: Register, db: Session = Depends(get_db)):
    # Check if the user already exists
    existing_user = get_user_by_email(register_data.email, db)

    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
     # Generate OTP
    otp = generateOTP()
    
    # Create the new user
    new_user = add_user(register_data, db)
    
    # create the otp for user
    user_otp = create_or_update_otp(new_user, otp, "verify", db)

    # Commit the changes to the database
    db.commit()

    user_response_data = {
        "id": new_user.id,
        "created": new_user.created,
        "updated": new_user.updated,
        "email": new_user.email,
        "first_name": new_user.first_name,
        "last_name": new_user.last_name,
        "email_verified": new_user.email_verified,
        "otp": user_otp.otp if user_otp.type == "verify" else None  # Include OTP only if the type matches the requested OTP type
    }

    return user_response_data


@router.post('/verify-email', summary="Verify email with OTP")
async def verify_email(verify_data: VerifyEmail, db: Session = Depends(get_db)):
    # Retrieve the user by email
    user = get_user_by_email(verify_data.email, db)
    
    # Check if the user exists
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    verify_otp = get_otp(user, "verify", db)

    # Check if OTP matches
    if verify_otp.otp != verify_data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Update email_verified flag to True
    user.email_verified = True
    # user.otp = None
    db.commit()
    
    return {"message": "Email verified successfully"}


@router.post("/login")
async def login(data: Login, db: Session = Depends(get_db)):
    #get user from the database
    user = get_user_by_email(data.email, db)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.email_verified:
        # Check if user email_verified.
        raise HTTPException(status_code=401, detail="Please verify your email first")
    
    if not user or not verify_password(data.password, user.password):
        # Check if user exists or if the provided password is incorrect
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    access_token = create_access_token(subject={"email":user.email, "id": user.id})
    refresh_token = create_refresh_token(subject={"email":user.email, "id": user.id})

    return {"access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user":{"id":user.id,
                    "email": user.email
                    }
            }


@router.post('/send-otp', summary="Request for OTP")
async def request_reset_password_otp(request_data: OtpRequest, db: Session = Depends(get_db)):
    
    otp_type = request_data.type
    
    if otp_type not in ['verify', 'forgot']:
    # check Type is valid
        raise HTTPException(status_code=401, detail="Type not valid, Choose type [verify or forgot]")

    #get user from the database
    user = get_user_by_email(request_data.email, db)
    
    # Check if the user exists
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate OTP
    otp = generateOTP()
    
    # create the otp for user
    user_otp = create_or_update_otp(user, otp, otp_type, db)
    
    # Commit the changes to the database
    db.commit()
    
    return {"email": user.email, "otp": user_otp.otp, "name": user.first_name}


@router.post('/reset-password', summary="Reset password with OTP")
async def reset_password_with_otp(request_data: ResetPasswordRequest, db: Session = Depends(get_db)):
    # Retrieve the user by email
    user = get_user_by_email(request_data.email, db)
    
    # Check if the user exists
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    verify_otp = get_otp(user, "forgot", db)
    
    if not verify_otp:
        raise HTTPException(status_code=404, detail="Please resent otp again")

    # Check if OTP matches
    if verify_otp.otp != request_data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Check if new password and confirm password match
    print(request_data.password, request_data.confirm_password, ":::::::::::::::::")
    if request_data.password != request_data.confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm password do not match")
    
    # Update user's password
    update_user_password(user, request_data.password, db)

    # Delete the verify_otp object
    db.delete(verify_otp)
    #set otp as none
    db.commit()
    
    return {"message": "Password reset successfully"}


@router.post('/change-password', summary="Reset password with old password")
async def reset_password(change_password_data: ChangePasswordRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Check if old password matches the existing password
    if not verify_password(change_password_data.old_password, current_user.password):
        raise HTTPException(status_code=400, detail="Incorrect old password")

    # Check if new password and confirm password match
    if change_password_data.new_password != change_password_data.confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm password do not match")

    # Update user's password
    update_user_password(current_user, change_password_data.new_password, db)
    
    return {"message": "Password reset successfully"}


@router.get('/user/{user_id}/', response_model=UserResponse)
def get_user_by_id(user_id: int, db: Session = Depends(get_db)):
    user = get_user_by_user_id(user_id, db)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user
