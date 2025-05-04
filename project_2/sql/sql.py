# ------------------- Imports -------------------
from fastapi import FastAPI, Response, HTTPException, Header, Depends
from typing import Optional, List
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker, declarative_base, Session
import re
from jose import JWTError, jwt

# ------------------- CONFIG -------------------
app = FastAPI()

SECRET_KEY = "449project"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MYSQL_URL = "mysql+mysqlconnector://root:449project@localhost/grocerystore"

engine = create_engine(MYSQL_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ------------------- SQLALCHEMY MODELS -------------------
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    role = Column(String(20), default="user")

class InventoryTable(Base):
    __tablename__ = "inventory"
    id = Column(Integer, primary_key=True, index=True)
    item_name = Column(String(100), nullable=False)
    description = Column(String(200))
    quantity = Column(Integer)
    price = Column(Float)
    manufacturer = Column(String(100))
    rating = Column(Float)
    owner = Column(String(50))

Base.metadata.create_all(bind=engine)

# ------------------- DB DEPENDENCY -------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------- PYDANTIC MODELS -------------------
class RegisterModel(BaseModel):
    username: str = Field(..., min_length=3)
    password: str
    email: EmailStr
    role: Optional[str] = "user"

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must be ≥8 chars and contain a special character")
        return v

class LoginModel(BaseModel):
    username: str
    password: str

class InventoryModel(BaseModel):
    item_name: str
    description: str
    quantity: int
    price: float
    manufacturer: str
    rating: float
    owner: Optional[str] = None

class UserInDB(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str

class User(BaseModel):
    id: int
    username: str
    role: str

class InventoryInDB(InventoryModel):
    id: int

# ------------------- UTILS -------------------
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta, "sub": data["username"]})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

async def get_user(username: str, db: Session) -> Optional[UserInDB]:
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        return None
    return UserInDB(id=user.id, username=user.username, email=user.email, role=user.role)

# ------------------- AUTH DEPENDENCY -------------------
async def get_current_user(x_access_token: str = Header(..., alias="x-access-token"), db: Session = Depends(get_db)) -> UserInDB:
    payload = await decode_token(x_access_token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = await get_user(username=username, db=db)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

# ------------------- AUTH ROUTES -------------------
@app.post("/register", status_code=201)
async def register(data: RegisterModel, db: Session = Depends(get_db)):
    if db.query(UserTable).filter(UserTable.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    if db.query(UserTable).filter(UserTable.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already taken")

    new_user = UserTable(
        username=data.username,
        password=data.password,  # NOTE: Don't store plaintext in production
        email=data.email,
        role=data.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully", "user_id": new_user.id}

@app.post("/login")
async def login(response: Response, creds: LoginModel, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.username == creds.username).first()

    if not user or user.password != creds.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(
        {"username": user.username, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    response.set_cookie("Username", user.username, httponly=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    return {"message": "Login successful", "token": token, "role": user.role}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("Username")
    return {"message": "Logout successful"}

# ------------------- INVENTORY ROUTES -------------------
@app.post("/inventory", response_model=InventoryInDB, status_code=201)
async def create_item(item: InventoryModel, current: UserInDB = Depends(get_current_user), db: Session = Depends(get_db)):
    owner = item.owner if current.role == "admin" and item.owner else current.username
    new_item = InventoryTable(**item.dict(), owner=owner)
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return InventoryInDB(id=new_item.id, **item.dict(), owner=owner)

@app.get("/inventory", response_model=List[InventoryInDB])
async def list_items(current: UserInDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current.role == "admin":
        items = db.query(InventoryTable).all()
    else:
        items = db.query(InventoryTable).filter(InventoryTable.owner == current.username).all()
    return [InventoryInDB(id=item.id, **item.__dict__) for item in items]

@app.get("/inventory/{item_id}", response_model=InventoryInDB)
async def get_item(item_id: int, current: UserInDB = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.query(InventoryTable).filter(InventoryTable.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if current.role != "admin" and item.owner != current.username:
        raise HTTPException(status_code=403, detail="Not allowed")
    return InventoryInDB(id=item.id, **item.__dict__)

@app.put("/inventory/{item_id}", response_model=InventoryInDB)
async def update_item(item_id: int, item: InventoryModel, current: UserInDB = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(InventoryTable).filter(InventoryTable.id == item_id).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Item not found")
    if current.role != "admin" and existing.owner != current.username:
        raise HTTPException(status_code=403, detail="Not allowed")

    for key, value in item.dict(exclude_unset=True).items():
        setattr(existing, key, value)

    if current.role != "admin":
        existing.owner = current.username

    db.commit()
    db.refresh(existing)
    return InventoryInDB(id=existing.id, **existing.__dict__)

@app.delete("/inventory/{item_id}", status_code=200)
async def delete_item(item_id: int, current: UserInDB = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.query(InventoryTable).filter(InventoryTable.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if current.role != "admin" and item.owner != current.username:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.delete(item)
    db.commit()
    return {"message": "Item deleted successfully"}
