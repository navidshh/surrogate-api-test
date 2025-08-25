from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
import re
# from ..redis_client import redis_client

from ..auth.dependency_functions import admin_required

router = APIRouter()

def get_redis(request: Request) -> Redis:
    """Dependency that provides the Redis client."""
    return request.app.state.redis_client

@router.get("/active-tasks")
async def list_active_tasks(
    _: dict = Depends(admin_required),   # enforce admin
    redis: Redis = Depends(get_redis),   # provide redis client
):
    """
    List all users with active tasks and their counts.
    """
    keys = await redis.keys("active_tasks:*")
    tasks = []

    for key in keys:
        count = await redis.get(key)
        user_id = key.split(":")[1]
        tasks.append({"user_id": user_id, "active_count": int(count)})

    return {"active_tasks": tasks}


@router.delete("/active-tasks/{user_id}")
async def reset_user_tasks(
    user_id: str,
    _: dict = Depends(admin_required),
    redis: Redis = Depends(get_redis),
):
    """
    Reset/delete active task counter for a specific user.
    """
    deleted = await redis.delete(f"active_tasks:{user_id}")
    if deleted:
        return {"detail": f"Reset active tasks for user {user_id}."}
    else:
        return JSONResponse(
            status_code=404,
            content={"detail": "No active task counter found for user."},
        )


@router.delete("/active-tasks")
async def reset_all_tasks(
    _: dict = Depends(admin_required),
    redis: Redis = Depends(get_redis),
):
    """
    Reset/delete all active task counters (dangerous in production).
    """
    keys = await redis.keys("active_tasks:*")
    if not keys:
        return {"detail": "No active task counters found."}

    deleted_count = await redis.delete(*keys)
    return {"detail": f"Deleted {deleted_count} active task counters."}


@router.get("/active-tasks-count")
async def total_active_task_count(
    _: dict = Depends(admin_required),
    redis: Redis = Depends(get_redis),
):
    """
    Get the sum of all active task counts across users.
    """
    keys = await redis.keys("active_tasks:*")
    total = 0
    for key in keys:
        count = await redis.get(key)
        total += int(count)

    return {"total_active_tasks": total}