# main.pyV
import os
from typing import List, Optional

from fastapi import (
    FastAPI, HTTPException, Depends, status, Response, Cookie
)
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Settings(BaseModel):
    authjwt_secret_key: str = SECRET_KEY
    authjwt_access_token_expires: int = 1800  # 30 minutes

@AuthJWT.load_config
def get_config():
    return Settings()

app = FastAPI()
client = AsyncIOMotorClient(MONGO_URL)
db = client.grocerystore  # your grocery store database

# -----------------------------------------------------------------------------
# MODELS
# -----------------------------------------------------------------------------
class UserIn(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str

class ItemIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=300)
    quantity: int = Field(..., ge=0)
    price: float = Field(..., ge=0)
    owner_id: Optional[str] = None  # only admin may set this

class ItemOut(BaseModel):
    id: str
    name: str
    description: str
    quantity: int
    price: float
    owner_id: str

# -----------------------------------------------------------------------------
# UTILITIES
# -----------------------------------------------------------------------------
def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

async def get_current_user(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
    except AuthJWTException:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_id = Authorize.get_jwt_subject()
    user_doc = await db.users.find_one({"_id": ObjectId(user_id)}, {"password": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(user_doc["_id"]),
        "username": user_doc["username"],
        "role": user_doc["role"]
    }

# -----------------------------------------------------------------------------
# EVENTS
# -----------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    # ensure unique users
    await db.users.create_index("username", unique=True)
    await db.users.create_index("email", unique=True)
    # optimize item queries by owner
    await db.items.create_index("owner_id")

# -----------------------------------------------------------------------------
# AUTH ENDPOINTS
# -----------------------------------------------------------------------------
@app.post("/register", response_model=UserOut)
async def register(user: UserIn):
    if await db.users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already taken")
    if await db.users.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "role": "user"
    }
    res = await db.users.insert_one(user_doc)
    return UserOut(
        id=str(res.inserted_id),
        username=user.username,
        email=user.email,
        role="user"
    )

@app.post("/login")
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    Authorize: AuthJWT = Depends()
):
    user_doc = await db.users.find_one({"username": form_data.username})
    if not user_doc or not verify_password(form_data.password, user_doc["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = Authorize.create_access_token(
        subject=str(user_doc["_id"]),
        user_claims={"role": user_doc["role"]}
    )
    Authorize.set_access_cookies(access_token, response=response)
    return {"msg": "Logged in successfully"}

@app.post("/logout")
def logout(response: Response, Authorize: AuthJWT = Depends()):
    Authorize.unset_jwt_cookies(response=response)
    return {"msg": "Logged out successfully"}

# -----------------------------------------------------------------------------
# INVENTORY ENDPOINTS
# -----------------------------------------------------------------------------
@app.post("/items", response_model=ItemOut)
async def create_item(
    item: ItemIn,
    user=Depends(get_current_user)
):
    # determine owner
    if user["role"] == "admin" and item.owner_id:
        owner_id = item.owner_id
    else:
        owner_id = user["id"]
    # validate owner exists
    if not await db.users.find_one({"_id": ObjectId(owner_id)}):
        raise HTTPException(status_code=400, detail="Owner not found")
    doc = item.dict(exclude={"owner_id"})
    doc["owner_id"] = ObjectId(owner_id)
    res = await db.items.insert_one(doc)
    return ItemOut(
        id=str(res.inserted_id),
        owner_id=owner_id,
        **{k: doc[k] for k in ("name", "description", "quantity", "price")}
    )

@app.get("/items", response_model=List[ItemOut])
async def list_items(user=Depends(get_current_user)):
    query = {} if user["role"] == "admin" else {"owner_id": ObjectId(user["id"])}
    cursor = db.items.find(query)
    items = []
    async for d in cursor:
        items.append(ItemOut(
            id=str(d["_id"]),
            name=d["name"],
            description=d["description"],
            quantity=d["quantity"],
            price=d["price"],
            owner_id=str(d["owner_id"])
        ))
    return items

@app.get("/items/{item_id}", response_model=ItemOut)
async def get_item(item_id: str, user=Depends(get_current_user)):
    try:
        oid = ObjectId(item_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid item ID")
    d = await db.items.find_one({"_id": oid})
    if not d:
        raise HTTPException(status_code=404, detail="Item not found")
    if user["role"] != "admin" and str(d["owner_id"]) != user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    return ItemOut(
        id=str(d["_1 _id"]),
        name=d["name"],
        description=d["description"],
        quantity=d["quantity"],
        price=d["price"],
        owner_id=str(d["owner_id"])
    )

@app.put("/items/{item_id}", response_model=ItemOut)
async def update_item(
    item_id: str,
    item: ItemIn,
    user=Depends(get_current_user)
):
    try:
        oid = ObjectId(item_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid item ID")
    existing = await db.items.find_one({"_id": oid})
    if not existing:
        raise HTTPException(status_code=404, detail="Item not found")
    if user["role"] != "admin" and str(existing["owner_id"]) != user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    update_data = item.dict(exclude_unset=True, exclude={"owner_id"})
    # admin may reassign owner
    if user["role"] == "admin" and item.owner_id:
        if not await db.users.find_one({"_id": ObjectId(item.owner_id)}):
            raise HTTPException(status_code=400, detail="New owner not found")
        update_data["owner_id"] = ObjectId(item.owner_id)
    await db.items.update_one({"_id": oid}, {"$set": update_data})
    d = await db.items.find_one({"_id": oid})
    return ItemOut(
        id=str(d["_id"]),
        name=d["name"],
        description=d["description"],
        quantity=d["quantity"],
        price=d["price"],
        owner_id=str(d["owner_id"])
    )

@app.delete("/items/{item_id}")
async def delete_item(item_id: str, user=Depends(get_current_user)):
    try:
        oid = ObjectId(item_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid item ID")
    d = await db.items.find_one({"_id": oid})
    if not d:
        raise HTTPException(status_code=404, detail="Item not found")
    if user["role"] != "admin" and str(d["owner_id"]) != user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    await db.items.delete_one({"_id": oid})
    return {"msg": "Item deleted successfully"}

# -----------------------------------------------------------------------------
# RUN:
# uvicorn main:app --reload
# -----------------------------------------------------------------------------

