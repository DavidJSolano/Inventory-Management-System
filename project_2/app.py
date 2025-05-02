
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from datetime import datetime, timedelta
import re


app = FastAPI()

DATABASE_URL = "mysql+mysqlconnector://root:Prema$1998@localhost/inventory_db" # fix later
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()



"""Database Models"""

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    role = Column(String(10), default="user")

class InventoryItem(Base):
    __tablename__ = "inventory"

    id = Column(Integer, primary_key=True, index=True)
    item_name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=False)
    quantity = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)
    manufacturer = Column(String(100), nullable=False)
    rating = Column(Float, nullable=False)
    owner = Column(String(50), nullable=False)

Base.metadata.create_all(bind=engine)

"""Pydantic Schemas"""

class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr
    role: str = "user"

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    username: str
    password: str

class InventoryCreate(BaseModel):
    item_name: str
    description: str
    quantity: int
    price: float
    manufacturer: str
    rating: float

class InventoryOut(InventoryCreate):
    id: int
    owner: str
    class Config:
        orm_mode = True