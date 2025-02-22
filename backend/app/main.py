from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List
import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

from .password_manager import Keychain

load_dotenv()

app = FastAPI(title="Password Manager API")

# Get allowed origins from environment variable or use default for development
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

# Security configurations
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # Change in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory storage for user keychains (replace with database in production)
user_keychains: Dict[str, Keychain] = {}

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    password: Optional[str] = None

class PasswordEntry(BaseModel):
    domain: str
    password: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except jwt.JWTError:
        raise credentials_exception

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        if form_data.username not in user_keychains:
            keychain = Keychain.new(form_data.password)
            user_keychains[form_data.username] = keychain
        else:
            # Verify password by attempting to dump and load
            keychain = user_keychains[form_data.username]
            dump_data, _ = keychain.dump()
            Keychain.load(form_data.password, dump_data)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/passwords")
async def add_password(
    entry: PasswordEntry,
    username: str = Depends(get_current_user)
):
    keychain = user_keychains[username]
    keychain.set(entry.domain, entry.password)
    return {"message": "Password stored successfully"}

@app.get("/passwords/{domain}")
async def get_password(
    domain: str,
    username: str = Depends(get_current_user)
):
    keychain = user_keychains[username]
    password = keychain.get(domain)
    if password is None:
        raise HTTPException(status_code=404, detail="Password not found")
    return {"domain": domain, "password": password}

@app.get("/passwords")
async def list_passwords(username: str = Depends(get_current_user)):
    keychain = user_keychains[username]
    passwords = []
    for domain_key in keychain.data["kvs"].keys():
        try:
            password = keychain.get(domain_key)
            if password:
                passwords.append({"domain": domain_key, "password": password})
        except:
            continue
    return {"domains": passwords}

@app.delete("/passwords/{domain}")
async def delete_password(
    domain: str,
    username: str = Depends(get_current_user)
):
    keychain = user_keychains[username]
    if keychain.remove(domain):
        return {"message": "Password deleted successfully"}
    raise HTTPException(status_code=404, detail="Password not found") 