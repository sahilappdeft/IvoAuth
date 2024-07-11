import math
import random
from passlib.context import CryptContext


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_hashed_password(password: str) -> str:
    return password_context.hash(password)

def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)


# Random OTP generation
def generateOTP():
    digits = "0123456789"
    otpLength = 6
    otp = ""

    i = 0
    while i < otpLength:
        index = math.floor(random.random() * len(digits))
        otp = otp + digits[index]
        i += 1

    return otp

def normalize_email(email):
    """
    Normalize email address by converting domain part to lowercase.
    """
    return email.lower()