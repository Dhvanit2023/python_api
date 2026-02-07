from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
import pyodbc
import uvicorn
import pymssql
# ---------------- APP ----------------
app = FastAPI()

# ---------------- SECURITY ----------------
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------- DATABASE ----------------
conn_str = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=dhvanit.mssql.somee.com;"
    "DATABASE=dhvanit;"
    "UID=patelkano_SQLLogin_1;"
    "PWD=m44uaudal7;"
)

def get_db():
    return pymssql.connect(
        server="dhvanit.mssql.somee.com",
        user="patelkano_SQLLogin_1",
        password="m44uaudal7",
        database="dhvanit"
    )

# ---------------- MODELS ----------------
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str

# ---------------- ROUTES ----------------
@app.get("/")
def home():
    return {"status": "API running. Use POST /login or /register"}

# ---------- REGISTER ----------
@app.post("/register")
def register_user(data: RegisterRequest):
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Check user already exists
        cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (data.email,)
        )
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Email already registered")

        # Hash password
        hashed_password = pwd_context.hash(data.password)

        # Insert user
        cursor.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (data.email, hashed_password)
        )
        conn.commit()
        conn.close()

        return {"status": "success", "message": "User registered successfully"}

    except HTTPException:
        raise
    except Exception as e:
        print("REGISTER ERROR:", e)
        raise HTTPException(status_code=500, detail="Server error")

# ---------- LOGIN ----------
@app.post("/login")
def login_user(data: LoginRequest):
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, password FROM users WHERE email = ?",
            (data.email,)
        )
        user = cursor.fetchone()
        conn.close()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not pwd_context.verify(data.password, user[1]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = jwt.encode(
            {"user_id": user[0]},
            SECRET_KEY,
            algorithm=ALGORITHM
        )

        return {"status": "success", "token": token}

    except HTTPException:
        raise
    except Exception as e:
        print("LOGIN ERROR:", e)
        raise HTTPException(status_code=500, detail="Server error")

# ---------------- DIRECT RUN ----------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

