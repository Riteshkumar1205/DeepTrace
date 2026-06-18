import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]

class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env", extra="ignore")

    PROJECT_NAME: str = "DeepTrace AI"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "deeptrace-super-secret-key-32-chars-at-least-!!!")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_MINUTES", "30"))

    # Databases
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{PROJECT_ROOT / 'dev.db'}")

    # Frontend / URLs
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:3000")

    # Storage settings
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", str(PROJECT_ROOT / "storage" / "uploads"))
    REPORT_DIR: str = os.getenv("REPORT_DIR", str(PROJECT_ROOT / "storage" / "reports"))

    # Password reset and SMTP
    ENABLE_PASSWORD_RESET: bool = os.getenv("ENABLE_PASSWORD_RESET", "false").lower() == "true"
    SMTP_HOST: Optional[str] = os.getenv("SMTP_HOST")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: Optional[str] = os.getenv("SMTP_USER")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD")
    SMTP_FROM_EMAIL: Optional[str] = os.getenv("SMTP_FROM_EMAIL")

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]

    def validation_issues(self) -> List[str]:
        issues: List[str] = []
        if self.SECRET_KEY == "deeptrace-super-secret-key-32-chars-at-least-!!!":
            issues.append("SECRET_KEY is using the built-in development fallback. Set a unique secret in .env.")
        if not self.DATABASE_URL:
            issues.append("DATABASE_URL is missing.")
        if self.ENABLE_PASSWORD_RESET:
            missing = [
                name
                for name, value in {
                    "SMTP_HOST": self.SMTP_HOST,
                    "SMTP_USER": self.SMTP_USER,
                    "SMTP_PASSWORD": self.SMTP_PASSWORD,
                    "SMTP_FROM_EMAIL": self.SMTP_FROM_EMAIL,
                }.items()
                if not value
            ]
            if missing:
                issues.append(
                    "Password reset is enabled but SMTP configuration is incomplete: "
                    + ", ".join(missing)
                )
        return issues

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

def get_validation_issues() -> List[str]:
    return settings.validation_issues()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORT_DIR, exist_ok=True)
