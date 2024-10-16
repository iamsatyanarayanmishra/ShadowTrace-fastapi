from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # Import CORS Middleware
from app.routers import admin, user, scan
from app.database import engine, Base
from app.models import User, Admin

app = FastAPI()

# Define allowed origins
origins = [
    "http://127.0.0.1:5500",  # Add your frontend origin
    "http://localhost:5500",
    # You can add more origins as needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to restrict origins for better security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

app.include_router(admin.router)
app.include_router(user.router)
app.include_router(scan.router)
