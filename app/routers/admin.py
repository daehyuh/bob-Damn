from fastapi import APIRouter, HTTPException, Header, Query
from typing import Optional
import boto3
import jwt
import logging
import json
from datetime import datetime
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
cloudtrail_client = boto3.client('cloudtrail')

def verify_admin_token(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="인증 헤더가 없습니다")
    
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        
        logger.warning(f"사용자의 관리자 접근 시도: {payload.get('username')}")
        
        if payload.get('username') != 'admin':
            logger.warning(f"비관리자 사용자의 관리자 접근 시도: {payload.get('username')}")
        
        return payload
    except jwt.InvalidTokenException:
        logger.warning("관리자 접근에 잘못된 JWT 토큰 사용")
        raise HTTPException(status_code=401, detail="잘못된 토큰입니다")

@router.get("/users")
async def list_all_users(user_id: Optional[str] = Query(None)):
    """
    사용자 목록 조회 - IDOR 취약점 (Insecure Direct Object Reference)
    user_id 파라미터로 다른 사용자 정보에 접근 가능
    """
    logger.warning("인증 없이 사용자 목록 엔드포인트에 접근")
    
    from app.routers.users import get_db_connection
    
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        if user_id:
            # IDOR 취약점: 직접적인 객체 참조로 다른 사용자 데이터 접근
            query = f"SELECT id, username, email, created_at FROM users WHERE id = {user_id}"
            logger.critical(f"IDOR 취약점 시도: {query}")
        else:
            query = "SELECT id, username, email, created_at FROM users LIMIT 10"
            logger.warning("백도어 인증 없이 전체 사용자 목록 조회")
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        users = []
        for result in results:
            users.append({
                "id": result[0],
                "사용자명": result[1],
                "이메일": result[2],
                "생성일시": str(result[3]) if result[3] else None
            })
        
        return {"사용자목록": users}
    
    except Exception as e:
        logger.error(f"사용자 목록 조회 오류: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'connection' in locals():
            connection.close()

@router.post("/sudo-command")
async def execute_sudo_command(command: str, password: str = "password123"):
    """
    sudo 명령어 실행 - 권한 상승 취약점
    약한 비밀번호 검증으로 sudo 권한 획득 가능
    """
    logger.critical(f"sudo 명령어 실행 시도: {command}")
    
    import subprocess
    
    try:
        # 약한 비밀번호 검증
        if password in ["password123", "admin", "123456", "password", "root"]:
            logger.critical(f"약한 비밀번호로 sudo 권한 획득: {password}")
            
            # 위험한 명령어 차단
            dangerous_cmds = ["rm -rf", "format", "shutdown", "reboot", "dd if="]
            for dangerous in dangerous_cmds:
                if dangerous in command:
                    logger.error(f"위험한 명령어 차단: {command}")
                    raise HTTPException(status_code=403, detail="위험한 명령어는 실행할 수 없습니다")
            
            # sudo 명령어 실행 (시뮬레이션)
            if command.startswith("sudo "):
                actual_command = command[5:]  # "sudo " 제거
            else:
                actual_command = command
                
            result = subprocess.run(
                actual_command.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            logger.critical(f"sudo 명령어 실행 완료: {command} (return_code: {result.returncode})")
            
            return {
                "메시지": f"sudo 명령어가 실행되었습니다",
                "명령어": command,
                "반환_코드": result.returncode,
                "출력": result.stdout[:1000],
                "에러": result.stderr[:1000]
            }
        else:
            logger.warning(f"잘못된 sudo 비밀번호: {password}")
            raise HTTPException(status_code=401, detail="sudo 비밀번호가 잘못되었습니다")
            
    except subprocess.TimeoutExpired:
        logger.error(f"sudo 명령어 실행 시간 초과: {command}")
        raise HTTPException(status_code=408, detail="명령어 실행 시간 초과")
    except Exception as e:
        logger.error(f"sudo 명령어 실행 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/change-user-role")
async def change_user_role(user_id: int, new_role: str = "admin", admin_key: str = "admin123"):
    """
    사용자 역할 변경 - 수평적 권한 상승 취약점
    약한 admin_key로 다른 사용자를 관리자로 승격 가능
    """
    logger.critical(f"사용자 {user_id}의 역할을 {new_role}로 변경 시도")
    
    from app.routers.users import get_db_connection
    
    try:
        # 약한 관리자 키 검증
        if admin_key not in ["admin123", "masterkey", "superuser", "root123"]:
            logger.warning(f"잘못된 관리자 키: {admin_key}")
            raise HTTPException(status_code=403, detail="관리자 권한이 없습니다")
        
        logger.critical(f"약한 관리자 키로 권한 상승 성공: {admin_key}")
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # 사용자 역할 업데이트 (실제로는 로그만 기록)
        logger.critical(f"사용자 ID {user_id}의 역할이 {new_role}로 변경됨")
        
        # 역할 변경 시뮬레이션
        if new_role == "admin":
            logger.critical(f"사용자 {user_id}가 관리자 권한을 획득했습니다!")
            
        return {
            "메시지": f"사용자 {user_id}의 역할이 {new_role}로 변경되었습니다",
            "사용자_ID": user_id,
            "새로운_역할": new_role,
            "권한": ["사용자_관리", "시스템_접근", "DB_접근"] if new_role == "admin" else ["기본_사용자"]
        }
        
    except Exception as e:
        logger.error(f"사용자 역할 변경 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'connection' in locals():
            connection.close()

@router.post("/create-instance")
async def create_ec2_instance(instance_type: str = "t2.micro", user=None):
    logger.critical(f"EC2 인스턴스 생성 시도 (타입: {instance_type})")
    
    try:
        response = ec2_client.run_instances(
            ImageId='ami-0abcdef1234567890',  # Dummy AMI ID
            MinCount=1,
            MaxCount=1,
            InstanceType=instance_type,
            KeyName='vulnerable-webapp-key',
            SecurityGroupIds=['sg-vulnerable'],
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'vulnerable-instance-{datetime.now().strftime("%Y%m%d-%H%M%S")}'},
                        {'Key': 'CreatedBy', 'Value': 'vulnerable-webapp'},
                        {'Key': 'Purpose', 'Value': 'security-testing'}
                    ]
                }
            ]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        logger.critical(f"EC2 인스턴스가 생성되었습니다: {instance_id}")
        
        return {
            "메시지": "EC2 인스턴스가 성공적으로 생성되었습니다",
            "인스턴스_ID": instance_id,
            "인스턴스_타입": instance_type
        }
        
    except Exception as e:
        logger.error(f"EC2 인스턴스 생성 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cloudtrail-events")
async def get_recent_cloudtrail_events(hours: int = Query(default=1, le=24)):
    logger.warning(f"지난 {hours}시간 동안의 CloudTrail 이벤트에 접근")
    
    try:
        end_time = datetime.now()
        start_time = datetime.fromtimestamp(end_time.timestamp() - (hours * 3600))
        
        response = cloudtrail_client.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxItems=50
        )
        
        events = []
        for event in response.get('Events', []):
            events.append({
                '이벤트_시간': event['EventTime'].isoformat(),
                '이벤트_이름': event['EventName'],
                '사용자명': event.get('Username', 'N/A'),
                '소스_IP': event.get('SourceIPAddress', 'N/A'),
                '사용자_에이전트': event.get('UserAgent', 'N/A')
            })
        
        logger.info(f"{len(events)}개의 CloudTrail 이벤트를 조회했습니다")
        
        return {"이벤트목록": events, "개수": len(events)}
        
    except Exception as e:
        logger.error(f"CloudTrail 이벤트 조회 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/terminate-instance/{instance_id}")
async def terminate_instance(instance_id: str, user=None):
    logger.critical(f"EC2 인스턴스 종료 시도: {instance_id}")
    
    try:
        ec2_client.terminate_instances(InstanceIds=[instance_id])
        
        logger.critical(f"EC2 인스턴스가 종료되었습니다: {instance_id}")
        
        return {"메시지": f"인스턴스 {instance_id}의 종료가 시작되었습니다"}
        
    except Exception as e:
        logger.error(f"인스턴스 종료 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))