from fastapi import UploadFile, HTTPException, status
from app.core.constants import ALLOWED_FILE_TYPES, MAX_UPLOAD_SIZE

async def validate_upload_file(file: UploadFile) -> UploadFile:
    if file.content_type not in ALLOWED_FILE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_FILE_TYPES)}"
        )
    
    # Check file size (this is an approximation as we can't easily check size without reading)
    # A better approach for production might be checking Content-Length header 
    # or reading chunks. For this skeleton, we'll verify size by seeking.
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
    
    if file_size > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Max size: {MAX_UPLOAD_SIZE / 1024 / 1024}MB"
        )
        
    return file
