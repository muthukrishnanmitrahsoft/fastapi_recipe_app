from fastapi import FastAPI, HTTPException, Depends ,Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, ForeignKey,func
from sqlalchemy.orm import sessionmaker, Session, relationship

from sqlalchemy.ext.declarative import DeclarativeMeta,declarative_base
from typing import List, Optional
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt

DATABASE_URL = "sqlite:///./demo.db"
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base: DeclarativeMeta = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    recipes = relationship("Recipe", back_populates="user")
    reviews = relationship("Review", back_populates="reviewer")


class Recipe(Base):
    __tablename__ = "recipes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    ingredients = Column(Text, nullable=False)
    preparation_steps = Column(Text, nullable=False)
    cooking_time = Column(Integer, nullable=False)
    serving_size = Column(Integer, nullable=False)
    category = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Float)
    user = relationship("User", back_populates="recipes")
    reviews = relationship("Review", back_populates="recipe")

class Review(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    recipe_id = Column(Integer, ForeignKey("recipes.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Float)
    comment = Column(Text)
    recipe = relationship("Recipe", back_populates="reviews")
    reviewer = relationship("User", back_populates="reviews")


Base.metadata.create_all(bind=engine)


class UserInDB(BaseModel):
    username: str
    email: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    username: str
    email: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str

class RecipeIn(BaseModel):
    title: str
    description: str
    ingredients: str
    preparation_steps: str
    cooking_time: int
    serving_size: int
    category: str

class RecipeOut(BaseModel):
    id: int
    title: str
    description: str
    ingredients: str
    preparation_steps: str
    cooking_time: int
    serving_size: int
    category: str
    user_id: int
    rating: Optional[float]

class ReviewIn(BaseModel):
    rating: float
    comment: Optional[str]

class ReviewOut(BaseModel):
    id: int
    recipe_id: int
    user_id: int
    rating: float
    comment: Optional[str]

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_recipe_average_rating(recipe_id: int, db: Session = Depends(get_db)):
    avg_rating = db.query(func.avg(Review.rating)).filter(Review.recipe_id == recipe_id).scalar()
    return avg_rating if avg_rating is not None else 0.0



@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=400, detail="Incorrect username or password"
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/recipes", response_model=RecipeOut)
async def create_recipe(recipe: RecipeIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_recipe = Recipe(**recipe.dict(), user_id=current_user.id)
    db.add(db_recipe)
    db.commit()
    db.refresh(db_recipe)
    return db_recipe



@app.get("/recipes", response_model=List[RecipeOut])
async def get_all_recipes(db: Session = Depends(get_db)):
    recipes = db.query(Recipe).all()

    for recipe in recipes:
        recipe.rating =  await(get_recipe_average_rating(recipe.id, db))
    return recipes

@app.get("/recipes/{recipe_id}", response_model=RecipeOut)
async def get_recipe(recipe_id: int, db: Session = Depends(get_db)):
    recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    recipe.rating = await(get_recipe_average_rating(recipe.id, db))
    return recipe




@app.put("/recipes/{recipe_id}", response_model=RecipeOut)
async def update_recipe(recipe_id: int, recipe: RecipeIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_recipe = db.query(Recipe).filter(Recipe.id == recipe_id, Recipe.user_id == current_user.id).first()
    if not db_recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    for key, value in recipe.dict().items():
        setattr(db_recipe, key, value)
    db.commit()
    db.refresh(db_recipe)
    return db_recipe

@app.delete("/recipes/{recipe_id}")
async def delete_recipe(recipe_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_recipe = db.query(Recipe).filter(Recipe.id == recipe_id, Recipe.user_id == current_user.id).first()
    if not db_recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    db.delete(db_recipe)
    db.commit()
    return {"message": "Recipe deleted successfully"}


@app.get("/recipes/category/{category}", response_model=List[RecipeOut])
async def get_recipes_by_category(category: str, db: Session = Depends(get_db)):
    recipes = db.query(Recipe).filter(Recipe.category == category).all()
    if not recipes:
        raise HTTPException(status_code=404, detail=f"No recipes found in category: {category}")
    for recipe in recipes:
        recipe.rating =  await(get_recipe_average_rating(recipe.id, db))
    return recipes



@app.get("/search", response_model=List[RecipeOut])
async def search_recipes(
    category: Optional[str] = Query(None),
    ingredients: Optional[str] = Query(None),
    cooking_time_min: Optional[int] = Query(None),
    cooking_time_max: Optional[int] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Recipe)
    
    if category:
        query = query.filter(Recipe.category == category)
    if ingredients:
        query = query.filter(Recipe.ingredients.ilike(f"%{ingredients}%"))
    if cooking_time_min is not None:
        query = query.filter(Recipe.cooking_time >= cooking_time_min)
    if cooking_time_max is not None:
        query = query.filter(Recipe.cooking_time <= cooking_time_max)
    
    return query.all()


@app.post("/recipes/{recipe_id}/reviews", response_model=ReviewOut)
async def create_recipe_review(recipe_id: int, review: ReviewIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if not db_recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    if review.rating < 0 or review.rating > 5:
        raise HTTPException(status_code=400, detail="Rating must be between 0 and 5")
    db_review = Review(**review.dict(), recipe_id=recipe_id, user_id=current_user.id)
    db.add(db_review)
    db.commit()
    db.refresh(db_review)
    return db_review

@app.get("/recipes/{recipe_id}/reviews", response_model=List[ReviewOut])
async def get_recipe_reviews(recipe_id: int, db: Session = Depends(get_db)):
    reviews = db.query(Review).filter(Review.recipe_id == recipe_id).all()
    return reviews



if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
