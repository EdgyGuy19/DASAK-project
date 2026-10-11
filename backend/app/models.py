from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, String, func, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    email: Mapped[str] = mapped_column(String, unique=True)
    password: Mapped[str] = mapped_column(String)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.current_timestamp())

class Event(Base):
    __tablename__ = "events"

    event_id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[str] = mapped_column(DateTime, default=lambda: datetime.now().isoformat())
    username: Mapped[list[User]] = mapped_column(String(50))
    event_type: Mapped[str] = mapped_column(String(50))
    user_id: Mapped[int] = mapped_column(Integer())
    message: Mapped[str] = mapped_column(String(255))
    ip_src: Mapped[str] = mapped_column(String(50))
    http_request: Mapped[str] = mapped_column(String(255))
    status_code: Mapped[str] = mapped_column(String(20))