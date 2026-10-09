from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import models.user

engine = create_engine("sqlite:///./app.db")
models.user.Base.metadata.create_all(engine)

def get_db():
    db = Session(autocommit=False, autoflush=False, bind=engine)
    try:
        yield db
    finally:
        db.close()


