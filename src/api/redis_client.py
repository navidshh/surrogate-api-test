# redis_client.py
import redis.asyncio as redis
import logging
from .api_config import settings

logger = logging.getLogger(__name__)


async def init_redis() -> redis.Redis:
    """
    Initialize and return a Redis client.
    Raises an exception if Redis is unreachable.
    """
    REDIS_URL = f"redis://{settings.REDIS_ENDPOINT}:{settings.REDIS_PORT}/0?socket_connect_timeout=1&socket_timeout=1"
    logger.info(f"Attempting Redis connection at {REDIS_URL}")

    client = redis.from_url(REDIS_URL, decode_responses=True)

    try:
        pong = await client.ping()
        if pong != "PONG" and pong is not True:
            raise ConnectionError(f"Unexpected Redis PING response: {pong}")
        logger.info("Redis client configured successfully.")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to Redis at {REDIS_URL}: {e}")
        raise  # re-raise so app startup fails


async def close_redis(client: redis.Redis):
    """
    Gracefully close a Redis client.
    """
    try:
        await client.close()
        await client.connection_pool.disconnect()
        logger.info("Redis connection closed.")
    except Exception as e:
        logger.error(f"Error while closing Redis: {e}")
