from sqlalchemy import create_engine
from sqlalchemy.orm import Session

engine = create_engine("sqlite:///./app.db")

def get_db():
    db = Session(autocommit=False, autoflush=False, bind=engine)
    try:
        yield db
    finally:
        db.close()


