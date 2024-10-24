from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Boolean, ForeignKey, Enum, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.event import listens_for
from auth.utility.utilis import get_hashed_password
from auth.database import Base


class Model(Base):
    __abstract__ = True

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    created = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class User(Model):
    __tablename__ = "user"

    first_name = Column(String(64), nullable=False)
    last_name = Column(String(64), nullable=False)
    email = Column(String(150), nullable=False, unique=True)
    password = Column(String(128), nullable=False)
    email_verified = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    
    otp_types = relationship("OtpType", back_populates="user")  # Relationship definition


# Automatic password hashing before insert
@listens_for(User, 'before_insert')
def hash_password_before_insert(mapper, connection, target):
    target.password = get_hashed_password(target.password)


class OtpType(Model):
    __tablename__ = "userotp"

    class OtpChoices(Enum):
        forgot = 'forgot'
        verify = 'verify'

    otp = Column(String(6), nullable=True)
    type = Column(Enum("forgot", "verify", name="ValueTypes"), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))  # Define foreign key relationship

    # Define a composite unique constraint
    __table_args__ = (
        UniqueConstraint('user_id', 'type', name='_user_type_uc'),
    )

    user = relationship("User", back_populates="otp_types")
