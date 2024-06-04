from auth.database import engine
from fastapi import FastAPI
from auth.models import Base
from auth.views import router

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(router)

