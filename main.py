from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from datetime import timedelta, datetime
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
import models, schemas, auth, database
from logging_config import setup_logging
import logging
from pathlib import Path
import certifi
from apscheduler.schedulers.asyncio import AsyncIOScheduler

def print_time():
    """job to print time every minute."""
    logger = logging.getLogger(__name__)
    logger.info(f"Current time: {datetime.now()}")


# LIFECYCLE EVENTS

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Logic
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting up: Connecting to MongoDB...")
    database.db_manager.client = AsyncIOMotorClient(
        database.MONGO_URL,
        tls=True,
        tlsCAFile=certifi.where()
    )
    database.db_manager.db = database.db_manager.client[database.DB_NAME]
    
    # Create unique index for username to ensure no duplicates
    await database.db_manager.db["users"].create_index("username", unique=True)
    logger.info("MongoDB connected and index created.")

    # Start Scheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(print_time, 'interval', seconds=60)
    scheduler.start()
    
    # The application runs while this yield is active
    yield
    
    # Shutdown Logic
    scheduler.shutdown()
    if database.db_manager.client:
        database.db_manager.client.close()
    logger.info("Shutting down: MongoDB connection closed.")

app = FastAPI(
    title="Sample FastAPI auth project",
    description="Distributed System Node Registry with OAuth2 + MongoDB Atlas",
    version="2.0.1",
    lifespan=lifespan
)

# CORS Configuration
# This is necessary when the frontend runs on a different port or origin.
# We set allow_origins=["*"] for development simplicity, allowing any origin
# to connect to the API. In production, you would replace "*" with your 
# specific frontend domain (e.g., "https://yourfrontend.com").
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

# PUBLIC ROUTES

@app.post("/register", response_model=schemas.UserResponse)
async def register_user(user: schemas.UserCreate, db = Depends(database.get_db)):
    """
    Register a new Compute Node or Admin.
    Note the 'async def' and 'await' usage.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Registering user: {user.username}")
    # Check if user exists
    existing_user = await db["users"].find_one({"username": user.username})
    if existing_user:
        logger.warning(f"Registration failed: Username {user.username} already exists")
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    
    # Create User Dict (MongoDB Document)
    user_doc = models.UserInDB(
        username=user.username,
        hashed_password=hashed_password
    ).model_dump()
    
    # Insert into MongoDB
    new_user = await db["users"].insert_one(user_doc)
    
    # Fetch the created user to return it (to get the generated _id)
    created_user = await db["users"].find_one({"_id": new_user.inserted_id})
    
    logger.info(f"User registered successfully: {user.username}")
    return created_user

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db = Depends(database.get_db)):
    """
    OAuth2 compliant token login.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Login attempt for user: {form_data.username}")
    user = await db["users"].find_one({"username": form_data.username})
    
    if not user or not auth.verify_password(form_data.password, user["hashed_password"]):
        logger.warning(f"Login failed for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    refresh_token = auth.create_refresh_token(
        data={"sub": user["username"]}
    )
    logger.info(f"Login successful for user: {form_data.username}")
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/refresh", response_model=schemas.Token)
async def refresh_token(refresh_token: str = Depends(auth.oauth2_scheme), db = Depends(database.get_db)):
    """
    Get a new access token using a refresh token.
    """
    logger = logging.getLogger(__name__)
    try:
        username = auth.verify_refresh_token(refresh_token)
    except HTTPException:
        logger.warning("Refresh token validation failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user still exists
    user = await db["users"].find_one({"username": username})
    if not user:
        logger.warning(f"Refresh failed: User {username} not found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    # Optionally rotate refresh token here
    new_refresh_token = auth.create_refresh_token(
        data={"sub": username}
    )
    
    logger.info(f"Token refreshed for user: {username}")
    return {"access_token": access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}


# PROTECTED ROUTES

@app.get("/users/me", response_model=schemas.UserResponse)
async def read_users_me(current_user: dict = Depends(auth.get_current_user)):
    """
    Get details of the currently logged-in user.
    """
    return current_user

@app.get("/system/status")
async def get_system_status(current_user: dict = Depends(auth.get_current_user)):
    """
    Simulates a secure command endpoint for distributed nodes.
    """
    return {
        "status": "operational",
        "secret_data": "Whatever you want to hide",
        "authenticated_as": current_user["username"],
        "role": current_user["role"],
        "backend": "MongoDB Atlas"
    }


# Sample UI
@app.get("/", response_class=HTMLResponse)
async def read_root():
    """
    Reads the index.html file and serves it.
    """
    try:
        with open("index.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        print("ERROR: File not found")
        return "<h1>Error: index.html not found. Please ensure it is in the same directory as main.py.</h1>"