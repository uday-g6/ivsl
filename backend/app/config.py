from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    APP_NAME: str = "IVSL"
    APP_VERSION: str = "1.0.0"
    HOST: str = "127.0.0.1"
    PORT: int = 8001
    STORAGE_DIR: Path = BASE_DIR / "storage"
    DEVICES_DIR: Path = BASE_DIR / "storage" / "devices"
    UPLOAD_DIR: Path = BASE_DIR / "storage" / "uploads"
    EXTRACT_DIR: Path = BASE_DIR / "storage" / "extracted"
    REPORT_DIR: Path = BASE_DIR / "storage" / "reports"
    SNAPSHOTS_DIR: Path = BASE_DIR / "storage" / "snapshots"
    DB_PATH: Path = BASE_DIR / "storage" / "ivsl.db"
    MAX_UPLOAD_MB: int = 500
    MAX_EXTRACTED_MB: int = 2000
    MAX_FILE_COUNT: int = 50000
    MAX_FILES_PER_IPA: int = 200000
    MAX_DEVICE_STORAGE_GB: int = 512
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
for d in (settings.STORAGE_DIR, settings.DEVICES_DIR, settings.UPLOAD_DIR, settings.EXTRACT_DIR, settings.REPORT_DIR, settings.SNAPSHOTS_DIR):
    d.mkdir(parents=True, exist_ok=True)
