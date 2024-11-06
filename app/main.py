from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import admin, user, scan
from app.database import engine, Base
from app.models import User, Admin, Company

app = FastAPI()

# Define allowed origins for security
origins = [
    "http://127.0.0.1:5500",  # Frontend origin for development
    "http://localhost:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Restrict to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],   # Allow all headers
)

# Initialize database
Base.metadata.create_all(bind=engine)

# Include routers
app.include_router(admin.router)
app.include_router(user.router)
app.include_router(scan.router)
