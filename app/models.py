from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.database import Base

class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    company_id = Column(Integer, ForeignKey('company.id'))
    password = Column(String(100))

    # Relationship to Company (bidirectional)
    company = relationship("Company", back_populates="admins")
    # Relationship to track users created by this admin
    created_users = relationship("User", back_populates="created_by_admin")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)  # made non-nullable
    company_id = Column(Integer, ForeignKey('company.id'))  # ForeignKey corrected
    password = Column(String(100))
    name = Column(String(100), nullable=True)
    email = Column(String(100), unique=True, nullable=True)  # made non-nullable
    mobile = Column(String(20), nullable=True)
    dob = Column(DateTime, nullable=True)
    address = Column(String(255), nullable=True)
    email_verified = Column(Boolean, default=False)
    first_time_login = Column(Boolean, default=True)
    otp = Column(String(6), nullable=True)
    otp_expiration = Column(DateTime, nullable=True)
    admin_id = Column(Integer, ForeignKey('admins.id'))  # ForeignKey added

    # Relationships
    company = relationship("Company", back_populates="users")
    created_by_admin = relationship("Admin", back_populates="created_users")

class Company(Base):
    __tablename__ = "company"

    id = Column(Integer, primary_key=True, index=True)
    company_name = Column(String(100), unique=True, nullable=False)
    company_address = Column(String(100), unique=True, nullable=False)
    is_osint_subscribed = Column(Boolean, default=False)
    is_eDiscovery_subscribed = Column(Boolean, default=False)

    # Relationships to Admins and Users
    admins = relationship("Admin", back_populates="company", cascade="all, delete-orphan")
    users = relationship("User", back_populates="company", cascade="all, delete-orphan")
