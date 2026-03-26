"""ARGUS platform configuration loaded from environment variables."""

from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with defaults suitable for Docker Compose deployment."""

    # Application
    APP_NAME: str = "ARGUS"
    DEBUG: bool = False
    SECRET_KEY: str = "argus-dev-secret-change-in-production"
    BACKEND_PORT: int = 8000

    # PostgreSQL + TimescaleDB
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "argus"
    POSTGRES_USER: str = "argus"
    POSTGRES_PASSWORD: str = "argus"

    # Neo4j
    NEO4J_URI: str = "bolt://neo4j:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "neo4j"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # ML
    ML_DEVICE: str = "cpu"
    ML_MODEL_PATH: str = "./ml/models"
    ANOMALY_THRESHOLD: float = 0.85
    GNN_THRESHOLD: float = 0.90

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def database_url_sync(self) -> str:
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
