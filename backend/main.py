from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()


@app.get("/")
def login_page():
    return FileResponse("web/login.html")


@app.get("/user")
def user_page():
    return FileResponse("web/user.html")