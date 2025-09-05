from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from fastapi.responses import StreamingResponse
import boto3
import logging
import os
import uuid
import time
from typing import Optional
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

s3_client = boto3.client('s3')
cloudwatch = boto3.client('logs')

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        file_id = str(uuid.uuid4())
        s3_key = f"uploads/{file_id}_{file.filename}"
        
        logger.info(f"S3 버킷 {settings.S3_BUCKET_NAME}에 파일 {file.filename} 업로드 중")
        
        s3_client.upload_fileobj(
            file.file, 
            settings.S3_BUCKET_NAME, 
            s3_key,
            ExtraArgs={'ContentType': file.content_type or 'application/octet-stream'}
        )
        
        # CloudWatch 로그 그룹 생성 및 로그 기록 (선택적)
        try:
            cloudwatch.put_log_events(
                logGroupName='/aws/application/vulnerable-webapp',
                logStreamName='file-operations',
                logEvents=[
                    {
                        'timestamp': int(time.time() * 1000),  # Unix timestamp in milliseconds
                        'message': f"파일 업로드: {file.filename} -> {s3_key}"
                    }
                ]
            )
        except cloudwatch.exceptions.ResourceNotFoundException:
            # 로그 그룹이 없으면 생성
            try:
                cloudwatch.create_log_group(logGroupName='/aws/application/vulnerable-webapp')
                cloudwatch.create_log_stream(
                    logGroupName='/aws/application/vulnerable-webapp',
                    logStreamName='file-operations'
                )
                # 다시 로그 기록 시도
                cloudwatch.put_log_events(
                    logGroupName='/aws/application/vulnerable-webapp',
                    logStreamName='file-operations',
                    logEvents=[
                        {
                            'timestamp': int(time.time() * 1000),
                            'message': f"파일 업로드: {file.filename} -> {s3_key}"
                        }
                    ]
                )
                logger.info("CloudWatch 로그 그룹 및 스트림이 생성되었습니다")
            except Exception as log_error:
                logger.warning(f"CloudWatch 로깅 실패 (업로드는 성공): {log_error}")
        except Exception as log_error:
            logger.warning(f"CloudWatch 로깅 실패 (업로드는 성공): {log_error}")
        
        return {
            "메시지": "파일이 성공적으로 업로드되었습니다",
            "파일_ID": file_id,
            "파일명": file.filename,
            "S3_키": s3_key
        }
        
    except Exception as e:
        logger.error(f"파일 업로드 실패: {e}")
        raise HTTPException(status_code=500, detail=f"업로드 실패: {str(e)}")

@router.get("/download")
async def download_file(filename: str):
    try:
        logger.warning(f"파일 다운로드 시도: {filename}")
        
        if "../" in filename or filename.startswith("/"):
            logger.warning(f"디렉토리 탐색 공격 시도 감지: {filename}")
        
        file_path = f"uploads/{filename}"
        
        response = s3_client.get_object(Bucket=settings.S3_BUCKET_NAME, Key=file_path)
        
        def iter_file():
            for chunk in response['Body'].iter_chunks(chunk_size=8192):
                yield chunk
        
        return StreamingResponse(
            iter_file(),
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        logger.error(f"파일 다운로드 실패: {e}")
        raise HTTPException(status_code=404, detail="파일을 찾을 수 없습니다")

@router.post("/bulk-upload")
async def bulk_upload(count: int = Query(default=10, le=1000)):
    try:
        logger.warning(f"{count}개 파일 대량 업로드 시작")
        
        uploaded_files = []
        
        for i in range(count):
            file_key = f"bulk-upload/file_{i}_{uuid.uuid4()}.txt"
            large_content = "A" * 10000  # 10KB per file
            
            s3_client.put_object(
                Bucket=settings.S3_BUCKET_NAME,
                Key=file_key,
                Body=large_content.encode()
            )
            
            uploaded_files.append(file_key)
        
        logger.info(f"대량 업로드 완료: {count}개 파일 업로드됨")
        
        return {
            "메시지": f"{count}개 파일이 성공적으로 업로드되었습니다",
            "파일목록": uploaded_files
        }
        
    except Exception as e:
        logger.error(f"대량 업로드 실패: {e}")
        raise HTTPException(status_code=500, detail=f"대량 업로드 실패: {str(e)}")

@router.delete("/cleanup")
async def cleanup_files():
    try:
        logger.info("파일 정리 프로세스 시작")
        
        response = s3_client.list_objects_v2(
            Bucket=settings.S3_BUCKET_NAME,
            Prefix="bulk-upload/"
        )
        
        if 'Contents' in response:
            delete_objects = [{'Key': obj['Key']} for obj in response['Contents']]
            
            s3_client.delete_objects(
                Bucket=settings.S3_BUCKET_NAME,
                Delete={'Objects': delete_objects}
            )
            
            return {"메시지": f"{len(delete_objects)}개 파일이 삭제되었습니다"}
        
        return {"메시지": "삭제할 파일이 없습니다"}
        
    except Exception as e:
        logger.error(f"정리 실패: {e}")
        raise HTTPException(status_code=500, detail=f"정리 실패: {str(e)}")

@router.get("/list")
async def list_files(prefix: Optional[str] = None):
    try:
        list_params = {'Bucket': settings.S3_BUCKET_NAME}
        if prefix:
            list_params['Prefix'] = prefix
            
        response = s3_client.list_objects_v2(**list_params)
        
        files = []
        if 'Contents' in response:
            for obj in response['Contents']:
                files.append({
                    '파일명': obj['Key'],
                    '크기': obj['Size'],
                    '수정일시': obj['LastModified'].isoformat()
                })
        
        return {"파일목록": files}
        
    except Exception as e:
        logger.error(f"파일 목록 조회 실패: {e}")
        raise HTTPException(status_code=500, detail=f"목록 조회 실패: {str(e)}")