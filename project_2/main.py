# main.py

import re
from typing import Optional, List
from datetime import datetime, timedelta

from fastapi import (
    FastAPI, Request, Response, HTTPException,
    Depends, status, Header
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, validator
from motor.motor_asyncio import AsyncIOMotorClient
from jose import JWTError, jwt

# --- CONFIGURATION ---
SECRET_KEY = "449project"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "grocerystore"

# --- APP & DB INIT ---
app = FastAPI()
mongo = AsyncIOMotorClient(MONGO_URI)
db = mongo[DB_NAME]
users_coll = db["users"]
items_coll = db["items"]

# --- Pydantic Models ---
class RegisterModel(BaseModel):
    username: str = Field(..., min_length=3)
    password: str
    email: EmailStr
    role: Optional[str] = "user"

    @validator("password")
    def password_strength(cls, v):
        if len(v) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError(
                "Password must be ≥8 chars and contain a special character"
            )
        return v

class LoginModel(BaseModel):
    username: str
    password: str

class InventoryModel(BaseModel):
    item_name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    quantity: int = Field(..., ge=0)
    price: float = Field(..., ge=0)
    manufacturer: str = Field(..., min_length=1)
    rating: float = Field(..., ge=0, le=5)
    owner: Optional[str] = None  # admin may supply

class UserInDB(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str

class InventoryInDB(InventoryModel):
    id: str
    owner: str

# --- UTILS ---
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user(username: str) -> Optional[UserInDB]:
    doc = await users_coll.find_one({"username": username})
    if not doc:
        return None
    return UserInDB(
        id=str(doc["_id"]),
        username=doc["username"],
        email=doc["email"],
        role=doc["role"],
    )

async def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# --- DEPENDENCIES ---
async def get_current_user(
    x_access_token: str = Header(..., alias="x-access-token")
) -> UserInDB:
    payload = await decode_token(x_access_token)
    username: str = payload.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Token payload invalid")
    user = await get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# --- STARTUP: INDEXES ---
@app.on_event("startup")
async def ensure_indexes():
    # Unique username & email
    await users_coll.create_index("username", unique=True)
    await users_coll.create_index("email", unique=True)
    # For fast item lookups
    await items_coll.create_index("owner")

# --- AUTH ROUTES ---
@app.post("/register", status_code=201)
async def register(data: RegisterModel):
    # check existing
    if await users_coll.find_one({"$or": [
        {"username": data.username},
        {"email": data.email}
    ]}):
        raise HTTPException(400, "Username or email already taken")
    # store user
    res = await users_coll.insert_one({
        "username": data.username,
        "password": data.password,   # ideally hashed!
        "email": data.email,
        "role": data.role
    })
    return {"message": "User registered", "user_id": str(res.inserted_id)}

@app.post("/login")
async def login(response: Response, creds: LoginModel):
    user_doc = await users_coll.find_one({"username": creds.username})
    if not user_doc or user_doc["password"] != creds.password:
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token(
        {"username": creds.username, "role": user_doc["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    # Set a simple Username cookie (not used for auth)
    response.set_cookie(
        key="Username",
        value=creds.username,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    return {"message": "Login successful", "token": token, "role": user_doc["role"]}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("Username")
    return {"message": "Logout successful"}

# --- INVENTORY CRUD ---
@app.post("/inventory", response_model=InventoryInDB, status_code=201)
async def create_item(
    item: InventoryModel,
    current: UserInDB = Depends(get_current_user)
):
    doc = item.dict()
    if current.role != "admin":
        doc["owner"] = current.username
    else:
        doc["owner"] = doc.get("owner", current.username)
    res = await items_coll.insert_one(doc)
    return InventoryInDB(id=str(res.inserted_id), **doc)

@app.get("/inventory", response_model=List[InventoryInDB])
async def list_items(current: UserInDB = Depends(get_current_user)):
    query = {} if current.role == "admin" else {"owner": current.username}
    cursor = items_coll.find(query)
    items = []
    async for doc in cursor:
        items.append(InventoryInDB(
            id=str(doc["_id"]),
            **{k: doc[k] for k in InventoryModel.__fields__}
        ))
    return items

@app.get("/inventory/{item_id}", response_model=InventoryInDB)
async def get_item(item_id: str, current: UserInDB = Depends(get_current_user)):
    doc = await items_coll.find_one({"_id": __import__("bson").ObjectId(item_id)})
    if not doc:
        raise HTTPException(404, "Item not found")
    if current.role != "admin" and doc["owner"] != current.username:
        raise HTTPException(403, "Not allowed")
    return InventoryInDB(
        id=item_id,
        **{k: doc[k] for k in InventoryModel.__fields__}
        )

@app.put("/inventory/{item_id}", response_model=InventoryInDB)
async def update_item(
    item_id: str,
    item: InventoryModel,
    current: UserInDB = Depends(get_current_user)
):
    doc = await items_coll.find_one({"_id": __import__("bson").ObjectId(item_id)})
    if not doc:
        raise HTTPException(404, "Item not found")
    if current.role != "admin" and doc["owner"] != current.username:
        raise HTTPException(403, "Not allowed")
    updated = item.dict()
    # admin may override owner
    if current.role == "admin":
        updated["owner"] = updated.get("owner", doc["owner"])
    else:
        updated["owner"] = current.username
    await items_coll.update_one(
        {"_id": __import__("bson").ObjectId(item_id)},
        {"$set": updated}
    )
    return InventoryInDB(id=item_id, **updated)

@app.delete("/inventory/{item_id}", status_code=200)
async def delete_item(item_id: str, current: UserInDB = Depends(get_current_user)):
    doc = await items_coll.find_one({"_id": __import__("bson").ObjectId(item_id)})
    if not doc:
        raise HTTPException(404, "Item not found")
    if current.role != "admin" and doc["owner"] != current.username:
        raise HTTPException(403, "Not allowed")
    await items_coll.delete_one({"_id": __import__("bson").ObjectId(item_id)})
    return {"message": "Item deleted successfully"}
