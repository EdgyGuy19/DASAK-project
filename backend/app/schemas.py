from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8)

class LoginRequest(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    is_admin: bool
    created_at: datetime
    model_config = {"from_attributes": True}

class EventOut(BaseModel):
    event_id: str
    timestamp: datetime
    username: str | None
    event_type: str
    user_id: int | None
    message: str
    ip_src: str | None
    http_request: str | None
    status_code: int
    model_config = {"from_attributes": True}

class AlertOut(BaseModel):
    id: str
    timestamp: datetime
    rule: str
    username: str | None
    ip_src: str | None
    event_count: int
    status: bool
    message: str
    model_config = {"from_attributes": True}

class AlertStatusUpdate(BaseModel):
    status: bool = Field(strict=True)

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
