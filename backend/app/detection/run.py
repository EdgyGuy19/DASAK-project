from sqlalchemy.orm import Session

from ..database import engine
from .brute_force import run_all

if __name__ == "__main__":
    with Session(engine) as db:
        findings = run_all(db)
        for f in findings:
            print(f)