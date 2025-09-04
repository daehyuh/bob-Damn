import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_DEFAULT_REGION: str = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    
    # RDS Configuration
    USE_RDS: bool = os.getenv("USE_RDS", "false").lower() == "true"
    RDS_ENDPOINT: str = os.getenv("RDS_ENDPOINT", "")
    RDS_PORT: int = int(os.getenv("RDS_PORT", "3306"))
    RDS_USERNAME: str = os.getenv("RDS_USERNAME", "admin")
    RDS_PASSWORD: str = os.getenv("RDS_PASSWORD", "")
    RDS_DB_NAME: str = os.getenv("RDS_DB_NAME", "vulnerable_db")
    
    # Local Database (fallback)
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_USER: str = os.getenv("DB_USER", "root")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "vulnerable123")
    DB_NAME: str = os.getenv("DB_NAME", "vulnerable_db")
    
    JWT_SECRET: str = os.getenv("JWT_SECRET", "weak_secret_key_123")
    S3_BUCKET_NAME: str = os.getenv("S3_BUCKET_NAME", "vulnerable-test-bucket")
    
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "DEBUG")
    
    @property
    def database_config(self):
        """Get database configuration based on USE_RDS setting"""
        if self.USE_RDS and self.RDS_ENDPOINT:
            return {
                "host": self.RDS_ENDPOINT,
                "port": self.RDS_PORT,
                "user": self.RDS_USERNAME,
                "password": self.RDS_PASSWORD,
                "database": self.RDS_DB_NAME
            }
        else:
            return {
                "host": self.DB_HOST,
                "port": 3306,
                "user": self.DB_USER,
                "password": self.DB_PASSWORD,
                "database": self.DB_NAME
            }

settings = Settings()