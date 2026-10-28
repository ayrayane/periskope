"""One token bucket per GitLab instance in Valkey, shared by all of that instance's collector replicas."""
from __future__ import annotations

import asyncio
import time

from redis.asyncio import Redis

# KEYS[1] bucket; ARGV: capacity, refill per ms, now ms. Returns 0 when a token was taken, else ms to wait.
TAKE = """
local b = redis.call('HMGET', KEYS[1], 'tokens', 'at')
local cap, rate, now = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local tokens, at = tonumber(b[1]) or cap, tonumber(b[2]) or now
tokens = math.min(cap, tokens + (now - at) * rate)
local wait = 0
if tokens >= 1 then tokens = tokens - 1 else wait = math.ceil((1 - tokens) / rate) end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'at', now)
redis.call('PEXPIRE', KEYS[1], 120000)
return wait
"""


class Bucket:
    def __init__(self, redis: Redis, instance: str, per_minute: int):
        self.key, self.capacity, self.rate = f"rate:{instance}", max(1, per_minute // 6), per_minute / 60000
        self._take = redis.register_script(TAKE)

    async def acquire(self) -> None:
        while wait := int(await self._take(keys=[self.key], args=[self.capacity, self.rate, int(time.time() * 1000)])):
            await asyncio.sleep(wait / 1000)
