from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import boto3
import logging
import json
import time
import threading
from datetime import datetime
from app.core.config import settings
from app.routers.users import get_db_connection

router = APIRouter()
logger = logging.getLogger(__name__)

rds_client = boto3.client('rds')
cloudwatch = boto3.client('cloudwatch')

@router.post("/brute-force-attack")
async def simulate_brute_force_attack(
    target_user: str = Query(default="admin", description="Target username"),
    attempts: int = Query(default=50, le=200, description="Number of login attempts")
):
    """
    RDS 데이터베이스에 대한 무차별 대입 공격 시뮬레이션
    여러 번의 로그인 시도 실패를 생성하여 CloudWatch 알람을 트리거
    """
    logger.critical(f"사용자 {target_user}에 대한 무차별 대입 공격 시뮬레이션 시작")
    
    failed_attempts = 0
    successful_attempts = 0
    
    for i in range(attempts):
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            # Try random passwords
            fake_password = f"fake_password_{i}_{int(time.time())}"
            query = f"SELECT id FROM users WHERE username = '{target_user}' AND password = MD5('{fake_password}')"
            
            cursor.execute(query)
            result = cursor.fetchone()
            
            if result:
                successful_attempts += 1
                logger.warning(f"무차별 대입: {target_user} 로그인 성공 ({i+1}번째 시도)")
            else:
                failed_attempts += 1
                logger.warning(f"무차별 대입: 사용자 {target_user}의 {i+1}번째 로그인 시도 실패")
            
            connection.close()
            
            # Small delay to avoid overwhelming the database
            time.sleep(0.1)
            
        except Exception as e:
            failed_attempts += 1
            logger.error(f"무차별 대입 {i+1}번째 시도 오류로 실패: {e}")
    
    logger.critical(f"무차별 대입 공격 완료: 실패 {failed_attempts}회, 성공 {successful_attempts}회")
    
    return {
        "메시지": "무차별 대입 공격 시뮬레이션 완료",
        "대상_사용자": target_user,
        "총_시도수": attempts,
        "실패_시도수": failed_attempts,
        "성공_시도수": successful_attempts,
        "공격_지속시간": f"{attempts * 0.1:.1f}초"
    }

@router.post("/sql-injection-mass-query")
async def mass_sql_injection_queries(
    query_count: int = Query(default=100, le=500, description="Number of malicious queries")
):
    """
    대량의 SQL 인젝션 시도 실행
    광범위한 RDS 로그와 CloudWatch 메트릭 생성
    """
    logger.critical(f"{query_count}개 쿼리로 대량 SQL 인젝션 공격 시작")
    
    malicious_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' OR 1=1#",
        "admin'--",
        "' UNION SELECT username, password FROM users--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "1' AND SLEEP(5)--",
        "' UNION SELECT @@version--"
    ]
    
    executed_queries = []
    
    for i in range(query_count):
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            # Cycle through malicious payloads
            payload = malicious_payloads[i % len(malicious_payloads)]
            query = f"SELECT * FROM users WHERE username = '{payload}'"
            
            logger.warning(f"악성 쿼리 {i+1} 실행: {query}")
            
            try:
                cursor.execute(query)
                result = cursor.fetchall()
                executed_queries.append({
                    "query_id": i+1,
                    "payload": payload,
                    "status": "executed",
                    "result_count": len(result) if result else 0
                })
            except Exception as query_error:
                executed_queries.append({
                    "query_id": i+1,
                    "payload": payload,
                    "status": "failed",
                    "error": str(query_error)
                })
                logger.error(f"SQL 인젝션 쿼리 실패: {query_error}")
            
            connection.close()
            time.sleep(0.05)  # Small delay
            
        except Exception as e:
            logger.error(f"대량 SQL 인젝션 시도 {i+1} 실패: {e}")
    
    logger.critical(f"대량 SQL 인젝션 공격 완료: {len(executed_queries)}개 쿼리 실행됨")
    
    return {
        "메시지": "대량 SQL 인젝션 공격 완료",
        "총_쿼리수": query_count,
        "실행된_쿼리수": len(executed_queries),
        "샘플_쿼리": executed_queries[:10]  # 샘플로 처음 10개 반환
    }

@router.post("/connection-exhaustion")
async def simulate_connection_exhaustion(
    concurrent_connections: int = Query(default=20, le=50, description="Number of concurrent connections")
):
    """
    RDS 연결 풀을 고갈시키기 위해 다수의 동시 데이터베이스 연결 생성
    CloudWatch 연결 수 알람을 트리거
    """
    logger.critical(f"{concurrent_connections}개 연결로 연결 고갈 공격 시작")
    
    connections = []
    active_connections = 0
    
    def create_long_connection(connection_id: int):
        try:
            connection = get_db_connection()
            connections.append(connection)
            logger.warning(f"연결 {connection_id}가 설정되고 유지되고 있습니다")
            
            # Hold connection for extended time
            cursor = connection.cursor()
            cursor.execute("SELECT SLEEP(30)")  # Hold for 30 seconds
            
        except Exception as e:
            logger.error(f"연결 {connection_id} 실패: {e}")
        finally:
            if connection:
                connection.close()
                logger.info(f"연결 {connection_id} 종료")
    
    # Create concurrent connections
    threads = []
    for i in range(concurrent_connections):
        thread = threading.Thread(target=create_long_connection, args=(i+1,))
        threads.append(thread)
        thread.start()
        time.sleep(0.1)  # Stagger connection attempts
    
    logger.warning(f"{len(threads)}개의 동시 데이터베이스 연결을 생성했습니다")
    
    # Wait a bit then close connections
    time.sleep(5)
    
    return {
        "메시지": "연결 고갈 공격이 시작되었습니다",
        "동시_연결수": concurrent_connections,
        "참고사항": "고갈 시뮬레이션을 위해 연결을 30초 동안 유지합니다"
    }

@router.get("/rds-performance-impact")
async def create_performance_impact():
    """
    RDS 성능에 영향을 주기 위해 리소스 집약적인 쿼리 실행
    CloudWatch에서 CPU 및 메모리 사용률 스파이크 생성
    """
    logger.critical("RDS 성능 영향 시뮬레이션 시작")
    
    performance_queries = [
        "SELECT COUNT(*) FROM users u1 CROSS JOIN users u2 CROSS JOIN users u3",
        "SELECT * FROM users ORDER BY RAND()",
        "SELECT username, COUNT(*) FROM users GROUP BY username HAVING COUNT(*) > 0 ORDER BY COUNT(*) DESC",
        "SELECT DISTINCT username FROM users WHERE username LIKE '%a%' OR username LIKE '%e%' OR username LIKE '%i%'",
        "SELECT * FROM users WHERE email REGEXP '^[a-z]+@[a-z]+\\.[a-z]+'",
    ]
    
    executed_queries = []
    
    for i, query in enumerate(performance_queries):
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            start_time = time.time()
            logger.warning(f"성능 집약적 쿼리 {i+1} 실행: {query}")
            
            cursor.execute(query)
            result = cursor.fetchall()
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            executed_queries.append({
                "query_id": i+1,
                "execution_time": f"{execution_time:.2f} seconds",
                "result_count": len(result) if result else 0,
                "query": query[:100] + "..." if len(query) > 100 else query
            })
            
            logger.info(f"성능 쿼리 {i+1}이 {execution_time:.2f}초에 완료되었습니다")
            connection.close()
            
        except Exception as e:
            logger.error(f"성능 쿼리 {i+1} 실패: {e}")
            executed_queries.append({
                "query_id": i+1,
                "status": "failed",
                "error": str(e),
                "query": query[:100] + "..." if len(query) > 100 else query
            })
    
    logger.critical("RDS 성능 영향 시뮬레이션 완료")
    
    return {
        "메시지": "RDS 성능 영향 시뮬레이션 완료",
        "실행된_쿼리": executed_queries,
        "총_실행시간": sum(float(q["execution_time"].split()[0]) for q in executed_queries if "execution_time" in q)
    }

@router.post("/create-rds-instance")
async def create_vulnerable_rds_instance(
    instance_class: str = Query(default="db.t3.micro", description="RDS instance class"),
    publicly_accessible: bool = Query(default=True, description="Make RDS publicly accessible")
):
    """
    약한 보안 설정으로 취약한 RDS 인스턴스 생성
    RDS 생성에 대한 CloudTrail 이벤트 생성
    """
    logger.critical(f"취약한 RDS 인스턴스 생성 시도: {instance_class}")
    
    instance_identifier = f"vulnerable-db-{int(time.time())}"
    
    try:
        response = rds_client.create_db_instance(
            DBInstanceIdentifier=instance_identifier,
            DBInstanceClass=instance_class,
            Engine='mysql',
            MasterUsername='admin',
            MasterUserPassword='VulnerablePassword123',  # Weak password
            AllocatedStorage=20,
            PubliclyAccessible=publicly_accessible,
            SecurityGroupIds=['sg-vulnerable-rds'],  # Assume vulnerable security group exists
            BackupRetentionPeriod=0,  # No backups
            MultiAZ=False,  # Single AZ for cost
            StorageEncrypted=False,  # Unencrypted storage
            DeletionProtection=False,  # Easy to delete
            Tags=[
                {'Key': 'Purpose', 'Value': 'security-testing'},
                {'Key': 'CreatedBy', 'Value': 'vulnerable-webapp'},
                {'Key': 'Environment', 'Value': 'test'}
            ]
        )
        
        logger.critical(f"취약한 RDS 인스턴스가 생성되었습니다: {instance_identifier}")
        
        return {
            "메시지": "취약한 RDS 인스턴스 생성이 시작되었습니다",
            "인스턴스_식별자": instance_identifier,
            "인스턴스_클래스": instance_class,
            "공개_접근_가능": publicly_accessible,
            "보안_문제점": [
                "공개 접근 가능",
                "약한 비밀번호",
                "암호화 없음",
                "백업 없음",
                "삭제 보호 없음"
            ]
        }
        
    except Exception as e:
        logger.error(f"RDS 인스턴스 생성 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/terminate-rds-instance/{instance_id}")
async def terminate_rds_instance(instance_id: str):
    """
    RDS 인스턴스 종료
    CloudTrail 삭제 이벤트 생성
    """
    logger.critical(f"RDS 인스턴스 종료 시도: {instance_id}")
    
    try:
        response = rds_client.delete_db_instance(
            DBInstanceIdentifier=instance_id,
            SkipFinalSnapshot=True,  # Dangerous - no backup
            DeleteAutomatedBackups=True
        )
        
        logger.critical(f"RDS 인스턴스 종료가 시작되었습니다: {instance_id}")
        
        return {
            "메시지": f"RDS 인스턴스 {instance_id} 종료가 시작되었습니다",
            "경고": "최종 스냅샷이 생략되었습니다 - 데이터가 영구적으로 손실됩니다"
        }
        
    except Exception as e:
        logger.error(f"RDS 인스턴스 종료 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/rds-snapshots")
async def list_rds_snapshots():
    """
    RDS 스냅샷 목록 (데이터 노출 가능성)
    """
    logger.warning("RDS 스냅샷 목록 조회 - 데이터 노출 가능성")
    
    try:
        response = rds_client.describe_db_snapshots(MaxRecords=50)
        
        snapshots = []
        for snapshot in response.get('DBSnapshots', []):
            snapshots.append({
                'snapshot_id': snapshot['DBSnapshotIdentifier'],
                'instance_id': snapshot['DBInstanceIdentifier'],
                'status': snapshot['Status'],
                'created': snapshot['SnapshotCreateTime'].isoformat(),
                'encrypted': snapshot.get('Encrypted', False),
                'public': snapshot.get('AttributeNames', []) if 'AttributeNames' in snapshot else []
            })
        
        logger.info(f"{len(snapshots)}개의 RDS 스냅샷을 조회했습니다")
        
        return {
            "스냅샷_목록": snapshots,
            "개수": len(snapshots)
        }
        
    except Exception as e:
        logger.error(f"RDS 스냅샷 목록 조회 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))