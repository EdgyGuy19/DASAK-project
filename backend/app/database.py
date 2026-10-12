from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .models import Base


DATABASE_FILE = Path(__file__).resolve().parents[2] / "dasak.db"
engine = create_engine(
    f"sqlite:///{DATABASE_FILE}", connect_args={"check_same_thread": False}
)

def init_db():
    # Creates missing tables; it does not replace existing tables or records.
    Base.metadata.create_all(engine)

def get_db():
    with Session(engine) as db:
        yield db

