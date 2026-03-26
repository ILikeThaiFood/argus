"""Database connections: async PostgreSQL, Neo4j, and Redis."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# ---------------------------------------------------------------------------
# SQLAlchemy async engine (PostgreSQL / TimescaleDB via asyncpg)
# ---------------------------------------------------------------------------
engine = create_async_engine(
    settings.database_url,
    echo=settings.DEBUG,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create tables if they don't exist (development convenience)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ensured.")


# ---------------------------------------------------------------------------
# Neo4j async driver helper
# ---------------------------------------------------------------------------
_neo4j_driver = None


async def get_neo4j_driver():
    """Return a singleton Neo4j async driver, creating it on first call."""
    global _neo4j_driver
    if _neo4j_driver is None:
        try:
            from neo4j import AsyncGraphDatabase
            _neo4j_driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
            logger.info("Neo4j driver initialised.")
        except Exception as exc:
            logger.warning("Neo4j unavailable – running without graph DB: %s", exc)
    return _neo4j_driver


async def close_neo4j() -> None:
    global _neo4j_driver
    if _neo4j_driver is not None:
        await _neo4j_driver.close()
        _neo4j_driver = None


@asynccontextmanager
async def neo4j_session():
    """Async context manager yielding a Neo4j async session."""
    driver = await get_neo4j_driver()
    if driver is None:
        yield None
        return
    async with driver.session() as session:
        yield session


# ---------------------------------------------------------------------------
# Redis connection helper
# ---------------------------------------------------------------------------
_redis_client = None


async def get_redis():
    """Return a singleton Redis async client."""
    global _redis_client
    if _redis_client is None:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                max_connections=20,
            )
            await _redis_client.ping()
            logger.info("Redis connected.")
        except Exception as exc:
            logger.warning("Redis unavailable – running without cache/streams: %s", exc)
            _redis_client = None
    return _redis_client


async def close_redis() -> None:
    global _redis_client
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None
