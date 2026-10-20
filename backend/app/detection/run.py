from sqlalchemy.orm import Session

from ..database import engine
from .brute_force import run_all, persist_alerts

if __name__ == "__main__":
    with Session(engine) as db:
        findings = run_all(db)
        persist_alerts(db, findings)
        for f in findings:
            print(f)