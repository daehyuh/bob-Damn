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
        
        logger.info(f"Uploading file {file.filename} to S3 bucket {settings.S3_BUCKET_NAME}")
        
        s3_client.upload_fileobj(
            file.file, 
            settings.S3_BUCKET_NAME, 
            s3_key,
            ExtraArgs={'ContentType': file.content_type or 'application/octet-stream'}
        )
        
        cloudwatch.put_log_events(
            logGroupName='/aws/application/vulnerable-webapp',
            logStreamName='file-operations',
            logEvents=[
                {
                    'timestamp': int(time.time() * 1000),  # Unix timestamp in milliseconds
                    'message': f"File uploaded: {file.filename} to {s3_key}"
                }
            ]
        )
        
        return {
            "message": "File uploaded successfully",
            "file_id": file_id,
            "filename": file.filename,
            "s3_key": s3_key
        }
        
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@router.get("/download")
async def download_file(filename: str):
    try:
        logger.warning(f"Attempting to download file: {filename}")
        
        if "../" in filename or filename.startswith("/"):
            logger.warning(f"Potential directory traversal attempt: {filename}")
        
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
        logger.error(f"File download failed: {e}")
        raise HTTPException(status_code=404, detail="File not found")

@router.post("/bulk-upload")
async def bulk_upload(count: int = Query(default=10, le=1000)):
    try:
        logger.warning(f"Starting bulk upload of {count} files")
        
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
        
        logger.info(f"Bulk upload completed: {count} files uploaded")
        
        return {
            "message": f"Successfully uploaded {count} files",
            "files": uploaded_files
        }
        
    except Exception as e:
        logger.error(f"Bulk upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk upload failed: {str(e)}")

@router.delete("/cleanup")
async def cleanup_files():
    try:
        logger.info("Starting file cleanup process")
        
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
            
            return {"message": f"Deleted {len(delete_objects)} files"}
        
        return {"message": "No files to delete"}
        
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")

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
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'modified': obj['LastModified'].isoformat()
                })
        
        return {"files": files}
        
    except Exception as e:
        logger.error(f"File listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Listing failed: {str(e)}")