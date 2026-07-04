"""Platform configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = ROOT_DIR / "knowledge-base"
DATA_DIR = ROOT_DIR / "data"
PLAYBOOKS_DIR = KNOWLEDGE_DIR / "playbooks"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Aegis Sentinel"
    version: str = "1.0.0"
    deployment_profile: Literal["personal", "smb", "enterprise"] = "personal"
    log_level: str = "INFO"

    # Event bus
    event_bus_backend: Literal["memory", "redis"] = "memory"
    redis_url: str = "redis://localhost:6379/0"
    event_queue_maxsize: int = 10_000

    # Database / storage
    data_dir: Path = Field(default=DATA_DIR)
    knowledge_dir: Path = Field(default=KNOWLEDGE_DIR)
    sqlite_path: Path = Field(default=DATA_DIR / "aegis.db")

    # Detection
    detection_tier_max: int = 3
    correlation_window_seconds: int = 300
    auto_response_tier: int = 2

    # ML
    ml_model_path: Path = Field(default=DATA_DIR / "models" / "anomaly.joblib")
    ml_enabled: bool = True

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_key: str = ""

    # Watchdog
    watchdog_interval_seconds: int = 30
    watchdog_enabled: bool = True

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "models").mkdir(parents=True, exist_ok=True)
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()
