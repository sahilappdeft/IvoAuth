from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
import os

if os.getcwd() == "/home/ubuntu/IvoAuth":
    DATABASE_URL = "postgresql://ivoportal:Psdnj%%40Eecezc3233r@13.202.134.230:5432/ivoportal"
    engine = create_engine(DATABASE_URL)
else:
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
