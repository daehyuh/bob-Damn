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
async def list_all_users(user=None):
    logger.warning("적절한 인증 확인 없이 관리자 엔드포인트에 접근")
    
    try:
        connection = None  # This would normally connect to DB
        
        sample_users = [
            {"id": 1, "username": "admin", "email": "admin@example.com"},
            {"id": 2, "username": "user1", "email": "user1@example.com"},
            {"id": 3, "username": "test", "email": "test@example.com"}
        ]
        
        return {"사용자목록": sample_users}
    
    except Exception as e:
        logger.error(f"사용자 목록 조회 오류: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/create-role")
async def create_iam_role(role_name: str, user=None):
    logger.critical(f"IAM 역할 생성 시도: {role_name}")
    
    try:
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
            Description=f"Role created by vulnerable webapp at {datetime.now()}"
        )
        
        logger.critical(f"IAM 역할이 성공적으로 생성되었습니다: {role_name}")
        
        return {
            "메시지": f"역할 {role_name}이 성공적으로 생성되었습니다",
            "arn": response['Role']['Arn']
        }
        
    except Exception as e:
        logger.error(f"IAM 역할 생성 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/attach-policy")
async def attach_policy_to_role(role_name: str, policy_arn: str, user=None):
    logger.critical(f"역할 {role_name}에 정책 {policy_arn} 연결 시도")
    
    try:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        
        logger.critical(f"정책이 성공적으로 연결되었습니다: {policy_arn} -> {role_name}")
        
        return {"메시지": f"정책 {policy_arn}이 역할 {role_name}에 연결되었습니다"}
        
    except Exception as e:
        logger.error(f"정책 연결 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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