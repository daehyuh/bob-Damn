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

@router.post("/network-attack-simulation")
async def simulate_network_attack(
    target_hosts: str = Query(default="malicious-domain.com,suspicious-ip.net", description="Comma-separated target hosts"),
    attack_type: str = Query(default="brute-force", description="Attack type")
):
    """
    네트워크 기반 공격 시뮬레이션 - GuardDuty 탐지 가능
    악성 도메인 및 IP에 대한 네트워크 연결 시도
    """
    import requests
    import socket
    
    logger.critical(f"네트워크 공격 시뮬레이션 시작: {attack_type}")
    
    hosts = [host.strip() for host in target_hosts.split(',')]
    results = []
    
    # 악성 도메인/IP 목록
    malicious_targets = [
        "malicious-botnet.com",
        "c2-server.evil.com", 
        "phishing-site.bad",
        "cryptocurrency-stealer.net",
        "192.168.1.100",  # 내부 IP 스캔
        "10.0.0.1",        # 내부 네트워크
        "threat-intelligence.malware.com"
    ]
    
    # 기본 대상과 악성 대상 합치기
    all_targets = hosts + malicious_targets
    
    for target in all_targets[:10]:  # 최대 10개 제한
        try:
            logger.critical(f"았성 도메인/IP에 대한 네트워크 연결 시도: {target}")
            
            # DNS 조회 시도
            try:
                socket.gethostbyname(target)
                logger.warning(f"DNS 조회 성공: {target}")
            except socket.gaierror:
                logger.warning(f"DNS 조회 실패: {target} (안전함)")
            
            # HTTP 요청 시도 (GuardDuty가 탐지할 수 있는 비정상적인 아웃바운드 통신)
            try:
                response = requests.get(f"http://{target}", timeout=5, headers={
                    'User-Agent': 'Malware-Scanner-v1.0',  # 의심스러운 User-Agent
                })
                logger.critical(f"악성 도메인에 HTTP 연결 성공: {target} (상태: {response.status_code})")
                results.append({
                    "대상": target,
                    "상태": "연결_성공",
                    "HTTP_상태": response.status_code
                })
            except requests.RequestException as e:
                logger.warning(f"악성 도메인 연결 실패: {target} - {e}")
                results.append({
                    "대상": target,
                    "상태": "연결_실패",
                    "오류": str(e)[:100]
                })
            
            # 포트 스캔 시뮬레이션
            suspicious_ports = [22, 80, 443, 1337, 4444, 6667]  # 의심스러운 포트들
            for port in suspicious_ports[:3]:  # 3개 포트만 테스트
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                try:
                    # 실제 IP인 경우만 포트 스캔
                    if target.replace('.', '').isdigit() or '192.168' in target or '10.0' in target:
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            logger.critical(f"의심스러운 포트 열림 감지: {target}:{port}")
                        else:
                            logger.info(f"포트 닫힘: {target}:{port}")
                except Exception:
                    pass
                finally:
                    sock.close()
            
            time.sleep(0.5)  # 공격 간격
            
        except Exception as e:
            logger.error(f"네트워크 공격 시뮬레이션 오류: {target} - {e}")
    
    logger.critical(f"네트워크 공격 시뮬레이션 완료: {len(all_targets)}개 대상")
    
    return {
        "메시지": "네트워크 공격 시뮬레이션 완료",
        "공격_유형": attack_type,
        "대상_목록": all_targets[:10],
        "연결_결과": results,
        "경고": "GuardDuty에서 이 활동을 악성 네트워크 통신으로 탐지할 수 있습니다"
    }

@router.post("/tor-network-simulation")
async def simulate_tor_network_activity(
    tor_exit_nodes: int = Query(default=5, le=10, description="Number of Tor exit nodes to simulate")
):
    """
    Tor 네트워크 활동 시뮬레이션 - GuardDuty 탐지 가능
    알려진 Tor exit node IP들과 연결 시도
    """
    import requests
    
    logger.critical(f"Tor 네트워크 활동 시뮬레이션 시작: {tor_exit_nodes}개 노드")
    
    # 알려진 Tor Exit Node IP 주소들 (예시용, 실제 Tor IP들)
    tor_exit_ips = [
        "199.87.154.255",  # 알려진 Tor exit node
        "185.220.101.182", # 알려진 Tor exit node  
        "185.220.101.183", # 알려진 Tor exit node
        "199.195.248.76",  # 알려진 Tor exit node
        "185.220.102.8",   # 알려진 Tor exit node
        "185.220.102.7",   # 알려진 Tor exit node
        "199.195.251.84",  # 알려진 Tor exit node
        "185.220.103.119", # 알려진 Tor exit node
        "185.220.103.118", # 알려진 Tor exit node
        "199.195.252.139"  # 알려진 Tor exit node
    ]
    
    results = []
    
    for i in range(min(tor_exit_nodes, len(tor_exit_ips))):
        tor_ip = tor_exit_ips[i]
        try:
            logger.critical(f"Tor Exit Node로 의심스러운 네트워크 활동: {tor_ip}")
            
            # Tor 네트워크를 사용한 것처럼 보이는 HTTP 요청
            headers = {
                'User-Agent': 'Tor Browser 11.0.15',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # 알려진 악성 도메인들에 요청 (실제로는 연결되지 않음)
            malicious_domains = [
                "dark-web-marketplace.onion.to",
                "ransomware-c2.tor2web.io", 
                "illegal-content.onion.link",
                "bitcoin-mixer.onion.pet"
            ]
            
            for domain in malicious_domains[:2]:  # 2개만 테스트
                try:
                    # 실제 HTTP 요청 (대부분 실패할 것이지만 GuardDuty에서 탐지할 수 있는 패턴)
                    response = requests.get(f"http://{domain}", headers=headers, timeout=5)
                    logger.critical(f"Tor를 통한 악성 도메인 접근 시도: {domain}")
                    results.append({
                        "tor_exit_ip": tor_ip,
                        "대상_도메인": domain,
                        "상태": "연결_성공"
                    })
                except requests.RequestException as e:
                    logger.warning(f"Tor를 통한 악성 도메인 연결 실패: {domain} - {str(e)[:50]}")
                    results.append({
                        "tor_exit_ip": tor_ip,
                        "대상_도메인": domain,
                        "상태": "연결_실패"
                    })
            
            time.sleep(1)  # Tor 노드 간 대기
            
        except Exception as e:
            logger.error(f"Tor 네트워크 시뮬레이션 오류: {tor_ip} - {e}")
    
    logger.critical(f"Tor 네트워크 활동 시뮬레이션 완료")
    
    return {
        "메시지": "Tor 네트워크 활동 시뮬레이션 완료",
        "Tor_Exit_노드수": tor_exit_nodes,
        "사용된_IP": tor_exit_ips[:tor_exit_nodes],
        "연결_결과": results,
        "경고": "GuardDuty에서 이 활동을 Tor 네트워크 사용 및 악성 도메인 연결로 탐지할 수 있습니다"
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