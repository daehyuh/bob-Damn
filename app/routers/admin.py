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
        raise HTTPException(status_code=401, detail="No authorization header")
    
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        
        logger.warning(f"Admin access attempt by user: {payload.get('username')}")
        
        if payload.get('username') != 'admin':
            logger.warning(f"Non-admin user attempting admin access: {payload.get('username')}")
        
        return payload
    except jwt.InvalidTokenException:
        logger.warning("Invalid JWT token used for admin access")
        raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/users")
async def list_all_users(user=None):
    logger.warning("Admin endpoint accessed without proper authentication check")
    
    try:
        connection = None  # This would normally connect to DB
        
        sample_users = [
            {"id": 1, "username": "admin", "email": "admin@example.com"},
            {"id": 2, "username": "user1", "email": "user1@example.com"},
            {"id": 3, "username": "test", "email": "test@example.com"}
        ]
        
        return {"users": sample_users}
    
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/create-role")
async def create_iam_role(role_name: str, user=None):
    logger.critical(f"Attempting to create IAM role: {role_name}")
    
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
        
        logger.critical(f"IAM role created successfully: {role_name}")
        
        return {
            "message": f"Role {role_name} created successfully",
            "arn": response['Role']['Arn']
        }
        
    except Exception as e:
        logger.error(f"Failed to create IAM role: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/attach-policy")
async def attach_policy_to_role(role_name: str, policy_arn: str, user=None):
    logger.critical(f"Attempting to attach policy {policy_arn} to role {role_name}")
    
    try:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        
        logger.critical(f"Policy attached successfully: {policy_arn} to {role_name}")
        
        return {"message": f"Policy {policy_arn} attached to role {role_name}"}
        
    except Exception as e:
        logger.error(f"Failed to attach policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/create-instance")
async def create_ec2_instance(instance_type: str = "t2.micro", user=None):
    logger.critical(f"Attempting to create EC2 instance of type: {instance_type}")
    
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
        logger.critical(f"EC2 instance created: {instance_id}")
        
        return {
            "message": "EC2 instance created successfully",
            "instance_id": instance_id,
            "instance_type": instance_type
        }
        
    except Exception as e:
        logger.error(f"Failed to create EC2 instance: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cloudtrail-events")
async def get_recent_cloudtrail_events(hours: int = Query(default=1, le=24)):
    logger.warning(f"Accessing CloudTrail events for the last {hours} hours")
    
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
                'event_time': event['EventTime'].isoformat(),
                'event_name': event['EventName'],
                'username': event.get('Username', 'N/A'),
                'source_ip': event.get('SourceIPAddress', 'N/A'),
                'user_agent': event.get('UserAgent', 'N/A')
            })
        
        logger.info(f"Retrieved {len(events)} CloudTrail events")
        
        return {"events": events, "count": len(events)}
        
    except Exception as e:
        logger.error(f"Failed to retrieve CloudTrail events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/terminate-instance/{instance_id}")
async def terminate_instance(instance_id: str, user=None):
    logger.critical(f"Attempting to terminate EC2 instance: {instance_id}")
    
    try:
        ec2_client.terminate_instances(InstanceIds=[instance_id])
        
        logger.critical(f"EC2 instance terminated: {instance_id}")
        
        return {"message": f"Instance {instance_id} termination initiated"}
        
    except Exception as e:
        logger.error(f"Failed to terminate instance: {e}")
        raise HTTPException(status_code=500, detail=str(e))