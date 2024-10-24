import os
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

if os.getcwd() == "/home/ubuntu/IvoAuth":
    print("*********************")
    # Encode the password
    password = "Psdnj@Eecezc3233r"
    encoded_password = quote_plus(password)
    DATABASE_URL = f"postgresql://ivoportal:{encoded_password}@13.202.134.230:5432/ivoportal"
    engine = create_engine(DATABASE_URL)
else:
    print("&&&&&&&&&&&&&&&&&&&&&&&&")
    DATABASE_URL = "sqlite:///./test.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Database session generator"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
