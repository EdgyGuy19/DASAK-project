from typing import List
from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from sqlalchemy import ForeignKey
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "user_account"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(30))
    email: Mapped[EmailStr] = mapped_column(EmailStr, String(50))
    when_created: Mapped[datetime] = mapped_column(datetime, default=datetime.utcnow)
    model_config = {"from_attributes": True}
    def __repr__(self) -> str:
        return f"User(id={self.id!r}, username={self.username!r}, email={self.email!r}, when_created={self.when_created!r})"
