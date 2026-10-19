from datetime import datetime, timezone
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

    event_id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    username: Mapped[str | None] = mapped_column(String(50))
    event_type: Mapped[str] = mapped_column(String(50))
    user_id: Mapped[int | None] = mapped_column(Integer())
    message: Mapped[str] = mapped_column(String(255))
    ip_src: Mapped[str | None] = mapped_column(String(50))
    http_request: Mapped[str | None] = mapped_column(String(255))
    status_code: Mapped[int] = mapped_column(Integer())


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    rule: Mapped[str] = mapped_column(String)
    username: Mapped[str | None] = mapped_column(String(50))
    ip_src: Mapped[str | None] = mapped_column(String(50))
    event_count: Mapped[int] = mapped_column(Integer())
    status: Mapped[bool] = mapped_column(Boolean, default=True)
    message: Mapped[str] = mapped_column(String)
