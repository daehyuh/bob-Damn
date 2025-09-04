from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import logging
import boto3
import os
from pathlib import Path
from app.routers import users, admin, files, exploit, rds_attacks
from app.core.config import settings

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper()))
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Vulnerable Web Application",
    description="A deliberately vulnerable web application for AWS security testing",
    version="1.0.0",
    debug=settings.DEBUG
)

# Create static and templates directories if they don't exist
static_dir = Path("app/static")
templates_dir = Path("app/templates")

static_dir.mkdir(parents=True, exist_ok=True)
templates_dir.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

boto3.setup_default_session(
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_DEFAULT_REGION
)

app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(files.router, prefix="/api/v1/files", tags=["files"])
app.include_router(exploit.router, prefix="/api/v1/exploit", tags=["exploit"])
app.include_router(rds_attacks.router, prefix="/api/v1/rds", tags=["rds-attacks"])

@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    logger.info("Health check endpoint accessed")
    return {"status": "ok", "vulnerable": True}