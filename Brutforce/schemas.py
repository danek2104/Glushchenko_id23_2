from pydantic import BaseModel
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class TaskBase(BaseModel):
    filename: str

class TaskCreate(TaskBase):
    pass

class Task(TaskBase):
    id: int
    status: str
    result: Optional[str] = None
    user_id: int

    class Config:
        from_attributes = True 