from pydantic import BaseModel

class UserCreate(BaseModel):
    username : str
    password : str

class UserLogin(BaseModel):
    username: str
    password: str

class ShowUser(BaseModel):
    username: str
    class Config:
        orm_mode = True

        