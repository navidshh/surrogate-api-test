# routes/test.py
import os
from fastapi import APIRouter, BackgroundTasks, Response, HTTPException, Header, Depends
from ..auth.dependency_functions import get_current_token, require_user, TokenInfo
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import StreamingResponse
from fastapi import APIRouter, Depends, Request

import openpyxl
from io import BytesIO
from typing import Optional, Dict, Any, List
from ..auth.cognito import validate_token
import logging
import time
import redis.asyncio as redis
from redis import exceptions as redis_exceptions
from ..auth.dependency_functions import get_current_user
from ..api_config import settings
# from ..redis_client import redis_client


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

def get_redis(request: Request):
    """Dependency that provides the Redis client."""
    return request.app.state.redis_client




# Redis connection check
@router.get("/redis_check")
async def redis_check(redis = Depends(get_redis)):
    try:
        reply = await redis.ping()
        if reply:  # True means PONG
            return JSONResponse(status_code=200, content={
                "status": "ok",
                "message": "Redis connection is healthy"
            })
        else:
            return JSONResponse(status_code=503, content={
                "status": "error",
                "message": "Redis ping failed",
                "details": str(reply)
            })
    except Exception as e:
        return JSONResponse(status_code=503, content={
            "status": "error",
            "message": "Redis is unavailable",
            "details": str(e)
        })
    
@router.get("/ping")
async def ping_redis(redis = Depends(get_redis)):
    pong = await redis.ping()
    return {"status": "ok", "pong": pong}    
    

# --- Layer 1: Request Rate Limit Setup (MANUAL) ---
REQUEST_LIMIT_CONFIG = {
    # limit, window_in_seconds
    "free-tier": (2, 600),     # 1 request per 10 minutes (600 seconds)
    "premium-tier": (60, 60),    # 60 requests per minute
    "admin-tier": (1000, 86400), # 1000 requests per day
}

# --- Layer 2: Concurrency Limit Setup (The Gatekeeper) ---
CONCURRENCY_QUOTAS = {
    "free-tier": 2,
    "premium-tier": 5,
    "admin-tier": 20,
}

# --- Task Wrapper for Safe Decrement ---
async def task_wrapper(user_id: str, role: str, redis_client):
    concurrency_key = f"active_tasks:{user_id}"
    try:
        logger.info(f"Starting long running task for user '{user_id}' with role '{role}'...")
        time.sleep(5) 
        logger.info(f"Long running task for user '{user_id}' finished.")
    finally:
        if redis_client:
            logger.info(f"Decrementing concurrency counter for user {user_id}.")
            await redis_client.decr(concurrency_key)

async def is_redis_available(redis) -> bool:
    try:
        return await redis.ping()
    except redis_exceptions.RedisError:
        return False



@router.post("/rate-limited-task-simple/")
async def run_task_simple(
    background_tasks: BackgroundTasks,
    x_user_id: str = Header(...),
    x_user_role: str = Header("Free-Tier"),
    redis_client = Depends(get_redis)  # inject redis
):
    if not await is_redis_available(redis_client):
        return JSONResponse(
            status_code=503,
            content={"detail": "Service is temporarily unavailable (Redis down)."}
        )

    if x_user_role not in REQUEST_LIMIT_CONFIG:
        return JSONResponse(status_code=400, content={"detail": "Invalid user role specified."})
        
    # --- Check Layer 1: Manual Request Limit (The Shield) ---
    try:
        limit, window = REQUEST_LIMIT_CONFIG[x_user_role]
        
        # Create a key that is unique for the user AND the current time window
        current_timestamp = int(time.time())
        window_start_timestamp = int(current_timestamp / window) * window
        request_limit_key = f"requests:{x_user_role}:{x_user_id}:{window_start_timestamp}"
        
        # Use a pipeline to make the INCR and EXPIRE atomic
        pipe = redis_client.pipeline()
        pipe.incr(request_limit_key)
        pipe.expire(request_limit_key, time=window)
        results = await pipe.execute()
        
        current_hits = results[0]

        if current_hits > limit:
            logger.warning(f"Request limit shield hit for user {x_user_id}. Hits: {current_hits}, Limit: {limit}.")
            # Calculate remaining time in window for a more accurate Retry-After
            retry_after = window - (current_timestamp - window_start_timestamp)
            return JSONResponse(status_code=429, content={"detail": "API request rate limit exceeded."}, headers={"Retry-After": str(retry_after)})
            
        logger.info(f"Request limit check passed for {x_user_id}.")

    except (redis_exceptions.ConnectionError, redis_exceptions.TimeoutError):
        return JSONResponse(status_code=503, content={"detail": "Rate limiting service unavailable. Please try again later."})

    # --- Check Layer 2: Concurrency Limit (The Gatekeeper) ---
    concurrency_key = f"active_tasks:{x_user_id}"
    max_concurrency = CONCURRENCY_QUOTAS[x_user_role]
    
    current_count = await redis_client.incr(concurrency_key)
    
    try:
        if current_count > max_concurrency:
            logger.warning(f"Concurrency limit gatekeeper hit for user {x_user_id}. Has {current_count} active tasks, limit is {max_concurrency}.")
            await redis_client.decr(concurrency_key) # Revert the increment
            return JSONResponse(status_code=429, content={"detail": "You already have the maximum number of active tasks running."})
        
        logger.info(f"Concurrency check passed for user {x_user_id}. Starting task {current_count}/{max_concurrency}.")
        # background_tasks.add_task(task_wrapper, user_id=x_user_id, role=x_user_role, redis_client=redis_client)
        await task_wrapper(user_id=x_user_id, role=x_user_role, redis_client=redis_client)
        return {"status": "Task accepted and started."}
        
    except Exception as e:
        logger.error(f"An unexpected error occurred after incrementing concurrency counter: {e}. Reverting.")
        await redis_client.decr(concurrency_key)
        raise


@router.post("/rate-limited-task/")
async def run_task(
    background_tasks: BackgroundTasks,
    claims: dict = Depends(get_current_user),
    redis_client = Depends(get_redis)  # inject redis
):
    
    x_user_id = claims["sub"]    
    x_user_role = claims.get("cognito:groups", ["free-tier"])[0].lower()

    # If Redis is down entirely, we cannot do anything.
    if not await is_redis_available(redis_client):
        return JSONResponse(
            status_code=503,
            content={"detail": "Service is temporarily unavailable (Redis down)."}
        )

    if x_user_role not in REQUEST_LIMIT_CONFIG:
        return JSONResponse(status_code=400, content={"detail": "Invalid user role specified."})
        
    # --- Check Layer 1: Manual Request Limit (The Shield) ---
    try:
        limit, window = REQUEST_LIMIT_CONFIG[x_user_role]
        
        # Create a key that is unique for the user AND the current time window
        current_timestamp = int(time.time())
        window_start_timestamp = int(current_timestamp / window) * window
        request_limit_key = f"requests:{x_user_role}:{x_user_id}:{window_start_timestamp}"
        
        # Use a pipeline to make the INCR and EXPIRE atomic
        pipe = redis_client.pipeline()
        pipe.incr(request_limit_key)
        pipe.expire(request_limit_key, time=window)
        results = await pipe.execute()
        
        current_hits = results[0]

        if current_hits > limit:
            logger.warning(f"Request limit shield hit for user {x_user_id}. Hits: {current_hits}, Limit: {limit}.")
            # Calculate remaining time in window for a more accurate Retry-After
            retry_after = window - (current_timestamp - window_start_timestamp)
            return JSONResponse(status_code=429, content={"detail": "API request rate limit exceeded."}, headers={"Retry-After": str(retry_after)})
            
        logger.info(f"Request limit check passed for {x_user_id}.")

    except (redis_exceptions.ConnectionError, redis_exceptions.TimeoutError):
        return JSONResponse(status_code=503, content={"detail": "Rate limiting service unavailable. Please try again later."})

    # --- Check Layer 2: Concurrency Limit (The Gatekeeper) ---
    concurrency_key = f"active_tasks:{x_user_id}"
    max_concurrency = CONCURRENCY_QUOTAS[x_user_role]
    
    current_count = await redis_client.incr(concurrency_key)
    
    try:
        if current_count > max_concurrency:
            logger.warning(f"Concurrency limit gatekeeper hit for user {x_user_id}. Has {current_count} active tasks, limit is {max_concurrency}.")
            await redis_client.decr(concurrency_key) # Revert the increment
            return JSONResponse(status_code=429, content={"detail": "You already have the maximum number of active tasks running."})
        
        logger.info(f"Concurrency check passed for user {x_user_id}. Starting task {current_count}/{max_concurrency}.")
        # background_tasks.add_task(task_wrapper, user_id=x_user_id, role=x_user_role, redis_client=redis_client)
        await task_wrapper(user_id=x_user_id, role=x_user_role, redis_client=redis_client)
        return {"status": "Task accepted and started."}
        
    except Exception as e:
        logger.error(f"An unexpected error occurred after incrementing concurrency counter: {e}. Reverting.")
        await redis_client.decr(concurrency_key)
        raise    