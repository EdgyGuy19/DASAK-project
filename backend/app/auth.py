from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select, or_
from sqlalchemy.orm import Session

from app.eventsLogger import log_event

from .database import get_db
from .models import User
from .schemas import RegisterRequest, LoginRequest, UserOut, TokenOut
from .security import hash_password, verify_password, create_access_token, decode_access_token

router = APIRouter(tags=["auth"])
bearer = HTTPBearer()

@router.post("/register", response_model=UserOut, status_code=201)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.scalar(
        select(User).where(or_(User.username == data.username, User.email == data.email))
    )
    if existing:
        log_event(
                event_type="registration",
                status_code=409,
                message="User already registered",
                user_id=existing.id,
                username=existing.username,
                http_request=f"POST /register",
                ip_src="67.67.67.67", # Kan fixa om det behövs
            )
        raise HTTPException(status.HTTP_409_CONFLICT, "Username or email already taken")
    user = User(
        username=data.username,
        email=data.email,
        password=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_event(
        event_type="registration",
        status_code=201,
        message="User registered successfully",
        user_id=user.id,
        username=user.username,
        http_request=f"POST /register",
        ip_src="67.67.67.67", # Kan fixa om det behövs
    )
    return user

@router.post("/login", response_model=TokenOut)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == data.username))
    if user is None or not verify_password(data.password, user.password):
        log_event(
                event_type="login",
                status_code=401,
                message="Invalid credentials",
                user_id=user.id,
                username=user.username,
                http_request=f"POST /login",
                ip_src="67.67.67.67", # Kan fixa om det behövs
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    log_event(
                    event_type="login",
                    status_code=200,
                    message="User logged in successfully",
                    user_id=user.id,
                    username=user.username,
                    http_request=f"POST /login",
                    ip_src="67.67.67.67", # Kan fixa om det behövs
                )
    return TokenOut(access_token=create_access_token(user.id))

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    user_id = decode_access_token(creds.credentials)
    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        log_event(
            event_type="unauthorized_access",
            status_code=401,
            message="Unauthorized access attempt",
            user_id=user_id,
            username=None,
            http_request=f"GET /me",
            ip_src="67.67.67.67", # Kan fixa om det behövs
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user

@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    log_event(
        event_type="access",
        status_code=200,
        message="User accessed their profile",
        user_id=current_user.id,
        username=current_user.username,
        http_request=f"GET /me",
        ip_src="67.67.67.67", # Kan fixa om det behövs
    )
    return current_user