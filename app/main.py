from fastapi import FastAPI
from app.routers import admin, user
from app.database import engine, Base
from app.models import User, Admin

app = FastAPI()

Base.metadata.create_all(bind = engine)
app.include_router(admin.router)
app.include_router(user.router)

