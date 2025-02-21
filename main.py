import os

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from auth.database import engine
from auth.models import Base
from auth.views import router

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Ensure the 'uploads' directory exists
os.makedirs("uploads", exist_ok=True)

# Mount the uploads directory
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

app.include_router(router)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    error_list = []
    for error in  exc.errors():
        error_list.append(f"{error['loc'][1]} : {error['msg']}") 
        
    return JSONResponse(
        status_code=400,
        content={"detail": error_list},
    )