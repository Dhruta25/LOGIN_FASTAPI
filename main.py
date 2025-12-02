from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import models, schemas, auth
from database import engine
from auth import get_db, hash_password, verify_password, create_token, get_current_user

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# ---------------- SIGNUP ---------------- #
@app.post("/signup")
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    new_user = models.User(
        username=user.username,
        password=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

# ---------------- LOGIN ---------------- #
@app.post("/login")
def login(data: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == data.username).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"username": user.username})
    print("TOKEN",token)
    return {"access_token": token, "token_type": "bearer"}

# ---------------- PROTECTED ROUTE ---------------- #
@app.get("/profile")
def profile(current_user=Depends(get_current_user)):
    return {"message": f"Welcome {current_user.username}"}