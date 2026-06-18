import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parents[2]

class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True)

    PROJECT_NAME: str = "DeepTrace AI"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "deeptrace-super-secret-key-32-chars-at-least-!!!")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Databases
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{PROJECT_ROOT / 'dev.db'}")
    
    # Storage settings
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", str(PROJECT_ROOT / "storage" / "uploads"))
    REPORT_DIR: str = os.getenv("REPORT_DIR", str(PROJECT_ROOT / "storage" / "reports"))
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]

    # File Ingestion Engine configuration
    MAX_FILE_SIZE_MB: int = 500
    ALLOWED_EXTENSIONS: List[str] = [
        # Images
        "jpg", "jpeg", "png", "heic", "webp", "tiff",
        # Videos
        "mp4", "mov", "avi", "mkv",
        # Audio
        "mp3", "wav", "aac",
        # Documents
        "pdf", "docx", "pptx", "xlsx",
        # Archives
        "zip", "rar",
        # Executables
        "exe", "dll", "apk"
    ]

settings = Settings()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORT_DIR, exist_ok=True)
