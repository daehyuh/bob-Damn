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
    title="취약한 웹 애플리케이션",
    description="AWS 보안 테스트를 위한 의도적으로 취약한 웹 애플리케이션",
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

app.include_router(users.router, prefix="/api/v1/users", tags=["사용자"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["관리자"])
app.include_router(files.router, prefix="/api/v1/files", tags=["파일"])
app.include_router(exploit.router, prefix="/api/v1/exploit", tags=["익스플로잇"])
app.include_router(rds_attacks.router, prefix="/api/v1/rds", tags=["RDS 공격"])

@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    logger.info("상태 확인 엔드포인트에 접근했습니다")
    return {"상태": "정상", "취약점_존재": True}