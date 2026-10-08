from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse

from app.auth import router as auth_router, get_current_user
from app.models import User

app = FastAPI()

app.include_router(auth_router)



# Check whether the authenticated user is an admin
def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return current_user


@app.get("/")
def login_page():
    return FileResponse("web/login.html")


@app.get("/user")
def user_page():
    return FileResponse("web/user.html")

@app.get("/admin")
def admin_page():
    return FileResponse("web/admin.html")


@app.get("/api/admin/check")
def check_admin(admin: User = Depends(require_admin)):
    return {"admin": True}