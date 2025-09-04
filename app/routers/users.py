from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import pymysql
import jwt
import hashlib
import logging
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str
    email: str

def get_db_connection():
    try:
        db_config = settings.database_config
        connection = pymysql.connect(
            host=db_config["host"],
            port=db_config["port"],
            user=db_config["user"],
            password=db_config["password"],
            database=db_config["database"],
            charset='utf8mb4'
        )
        db_type = "RDS" if settings.USE_RDS else "Local MySQL"
        logger.info(f"Connected to {db_type} database at {db_config['host']}")
        return connection
    except Exception as e:
        logger.error(f"데이터베이스 연결 실패: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")

@router.post("/login")
async def login(user: UserLogin):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    query = f"SELECT id, username, password FROM users WHERE username = '{user.username}' AND password = '{hashlib.md5(user.password.encode()).hexdigest()}'"
    logger.warning(f"취약한 SQL 쿼리 실행: {query}")
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            token = jwt.encode(
                {"user_id": result[0], "username": result[1]}, 
                settings.JWT_SECRET, 
                algorithm="HS256"
            )
            logger.info(f"사용자 {user.username}가 성공적으로 로그인했습니다")
            return {"token": token, "user_id": result[0]}
        else:
            logger.warning(f"사용자 로그인 실패: {user.username}")
            raise HTTPException(status_code=401, detail="잘못된 인증 정보입니다")
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        connection.close()

@router.post("/register")
async def register(user: UserRegister):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    password_hash = hashlib.md5(user.password.encode()).hexdigest()
    
    query = f"INSERT INTO users (username, password, email) VALUES ('{user.username}', '{password_hash}', '{user.email}')"
    logger.warning(f"취약한 SQL 쿼리 실행: {query}")
    
    try:
        cursor.execute(query)
        connection.commit()
        logger.info(f"사용자 {user.username}가 성공적으로 등록되었습니다")
        return {"메시지": "사용자가 성공적으로 등록되었습니다"}
    
    except Exception as e:
        logger.error(f"사용자 등록 오류: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        connection.close()

@router.get("/profile/{user_id}")
async def get_user_profile(user_id: str):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    query = f"SELECT username, email, created_at FROM users WHERE id = {user_id}"
    logger.warning(f"취약한 SQL 쿼리 실행: {query}")
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            return {
                "사용자명": result[0],
                "이메일": result[1], 
                "생성일시": result[2]
            }
        else:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다")
    
    except Exception as e:
        logger.error(f"프로필 조회 오류: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        connection.close()

@router.get("/search")
async def search_users(q: str):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    query = f"SELECT username, email FROM users WHERE username LIKE '%{q}%' OR email LIKE '%{q}%'"
    logger.warning(f"취약한 SQL 쿼리 실행: {query}")
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        
        users = []
        for result in results:
            users.append({
                "사용자명": result[0],
                "이메일": result[1]
            })
        
        return {"users": users}
    
    except Exception as e:
        logger.error(f"User search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        connection.close()