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
    Simulate brute force attack against RDS database
    Generates multiple failed login attempts to trigger CloudWatch alarms
    """
    logger.critical(f"Starting brute force attack simulation against user: {target_user}")
    
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
                logger.warning(f"Brute force: Successful login for {target_user} (attempt {i+1})")
            else:
                failed_attempts += 1
                logger.warning(f"Brute force: Failed login attempt {i+1} for user {target_user}")
            
            connection.close()
            
            # Small delay to avoid overwhelming the database
            time.sleep(0.1)
            
        except Exception as e:
            failed_attempts += 1
            logger.error(f"Brute force attempt {i+1} failed with error: {e}")
    
    logger.critical(f"Brute force attack completed: {failed_attempts} failed, {successful_attempts} successful")
    
    return {
        "message": "Brute force attack simulation completed",
        "target_user": target_user,
        "total_attempts": attempts,
        "failed_attempts": failed_attempts,
        "successful_attempts": successful_attempts,
        "attack_duration": f"{attempts * 0.1:.1f} seconds"
    }

@router.post("/sql-injection-mass-query")
async def mass_sql_injection_queries(
    query_count: int = Query(default=100, le=500, description="Number of malicious queries")
):
    """
    Execute large number of SQL injection attempts
    Generates extensive RDS logs and CloudWatch metrics
    """
    logger.critical(f"Starting mass SQL injection attack with {query_count} queries")
    
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
            
            logger.warning(f"Executing malicious query {i+1}: {query}")
            
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
                logger.error(f"SQL injection query failed: {query_error}")
            
            connection.close()
            time.sleep(0.05)  # Small delay
            
        except Exception as e:
            logger.error(f"Mass SQL injection attempt {i+1} failed: {e}")
    
    logger.critical(f"Mass SQL injection attack completed: {len(executed_queries)} queries executed")
    
    return {
        "message": "Mass SQL injection attack completed",
        "total_queries": query_count,
        "executed_queries": len(executed_queries),
        "sample_queries": executed_queries[:10]  # Return first 10 as sample
    }

@router.post("/connection-exhaustion")
async def simulate_connection_exhaustion(
    concurrent_connections: int = Query(default=20, le=50, description="Number of concurrent connections")
):
    """
    Create many concurrent database connections to exhaust RDS connection pool
    Triggers CloudWatch connection count alarms
    """
    logger.critical(f"Starting connection exhaustion attack with {concurrent_connections} connections")
    
    connections = []
    active_connections = 0
    
    def create_long_connection(connection_id: int):
        try:
            connection = get_db_connection()
            connections.append(connection)
            logger.warning(f"Connection {connection_id} established and held")
            
            # Hold connection for extended time
            cursor = connection.cursor()
            cursor.execute("SELECT SLEEP(30)")  # Hold for 30 seconds
            
        except Exception as e:
            logger.error(f"Connection {connection_id} failed: {e}")
        finally:
            if connection:
                connection.close()
                logger.info(f"Connection {connection_id} closed")
    
    # Create concurrent connections
    threads = []
    for i in range(concurrent_connections):
        thread = threading.Thread(target=create_long_connection, args=(i+1,))
        threads.append(thread)
        thread.start()
        time.sleep(0.1)  # Stagger connection attempts
    
    logger.warning(f"Created {len(threads)} concurrent database connections")
    
    # Wait a bit then close connections
    time.sleep(5)
    
    return {
        "message": "Connection exhaustion attack initiated",
        "concurrent_connections": concurrent_connections,
        "note": "Connections will be held for 30 seconds to simulate exhaustion"
    }

@router.get("/rds-performance-impact")
async def create_performance_impact():
    """
    Execute resource-intensive queries to impact RDS performance
    Generates CPU and memory usage spikes in CloudWatch
    """
    logger.critical("Starting RDS performance impact simulation")
    
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
            logger.warning(f"Executing performance-intensive query {i+1}: {query}")
            
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
            
            logger.info(f"Performance query {i+1} completed in {execution_time:.2f} seconds")
            connection.close()
            
        except Exception as e:
            logger.error(f"Performance query {i+1} failed: {e}")
            executed_queries.append({
                "query_id": i+1,
                "status": "failed",
                "error": str(e),
                "query": query[:100] + "..." if len(query) > 100 else query
            })
    
    logger.critical("RDS performance impact simulation completed")
    
    return {
        "message": "RDS performance impact simulation completed",
        "executed_queries": executed_queries,
        "total_execution_time": sum(float(q["execution_time"].split()[0]) for q in executed_queries if "execution_time" in q)
    }

@router.post("/create-rds-instance")
async def create_vulnerable_rds_instance(
    instance_class: str = Query(default="db.t3.micro", description="RDS instance class"),
    publicly_accessible: bool = Query(default=True, description="Make RDS publicly accessible")
):
    """
    Create a vulnerable RDS instance with weak security settings
    Generates CloudTrail events for RDS creation
    """
    logger.critical(f"Attempting to create vulnerable RDS instance: {instance_class}")
    
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
        
        logger.critical(f"Vulnerable RDS instance created: {instance_identifier}")
        
        return {
            "message": "Vulnerable RDS instance creation initiated",
            "instance_identifier": instance_identifier,
            "instance_class": instance_class,
            "publicly_accessible": publicly_accessible,
            "security_issues": [
                "Publicly accessible",
                "Weak password",
                "No encryption",
                "No backups",
                "No deletion protection"
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to create RDS instance: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/terminate-rds-instance/{instance_id}")
async def terminate_rds_instance(instance_id: str):
    """
    Terminate RDS instance
    Generates CloudTrail deletion events
    """
    logger.critical(f"Attempting to terminate RDS instance: {instance_id}")
    
    try:
        response = rds_client.delete_db_instance(
            DBInstanceIdentifier=instance_id,
            SkipFinalSnapshot=True,  # Dangerous - no backup
            DeleteAutomatedBackups=True
        )
        
        logger.critical(f"RDS instance termination initiated: {instance_id}")
        
        return {
            "message": f"RDS instance {instance_id} termination initiated",
            "warning": "Final snapshot skipped - data will be permanently lost"
        }
        
    except Exception as e:
        logger.error(f"Failed to terminate RDS instance: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/rds-snapshots")
async def list_rds_snapshots():
    """
    List RDS snapshots (potential data exposure)
    """
    logger.warning("Listing RDS snapshots - potential data exposure")
    
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
        
        logger.info(f"Retrieved {len(snapshots)} RDS snapshots")
        
        return {
            "snapshots": snapshots,
            "count": len(snapshots)
        }
        
    except Exception as e:
        logger.error(f"Failed to list RDS snapshots: {e}")
        raise HTTPException(status_code=500, detail=str(e))