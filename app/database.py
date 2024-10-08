from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "mysql+pymysql://root:Kanha&1satya@localhost/shadowtrace"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

try:
    connection = engine.connect()
    print("Connected successfully!")
    connection.close()
except Exception as e:
    print(f"Error connecting to the database: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
