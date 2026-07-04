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
    environment: Literal["development", "production"] = "development"
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
    auto_response_enabled: bool = False
    auto_response_tier: int = 2
    soar_cooldown_seconds: int = 60
    alert_dedup_window_seconds: int = 30

    # ML
    ml_model_path: Path = Field(default=DATA_DIR / "models" / "anomaly.joblib")
    ml_enabled: bool = True

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_key: str = "dev-key-change-in-production"
    rate_limit_per_minute: int = 120
    max_prompt_length: int = 32_000
    max_log_line_length: int = 16_000

    # Watchdog
    watchdog_interval_seconds: int = 30
    watchdog_enabled: bool = True

    # SOAR simulation mode (personal profile defaults to simulated actions)
    soar_simulation_mode: bool = True

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "models").mkdir(parents=True, exist_ok=True)
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)

    def require_api_key_in_production(self) -> None:
        if self.environment == "production" and (
            not self.api_key or self.api_key == "dev-key-change-in-production"
        ):
            raise RuntimeError(
                "API_KEY must be set to a strong secret when ENVIRONMENT=production"
            )


settings = Settings()
settings.ensure_dirs()
