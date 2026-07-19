from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4
    base_delay_seconds: float = 0.6
    max_delay_seconds: float = 8.0


def should_retry_http(status_code: int) -> bool:
    return status_code in {429, 500, 502, 503, 504}


def sleep_backoff(attempt: int, policy: RetryPolicy) -> None:
    # attempt starts at 1
    delay = min(policy.max_delay_seconds, policy.base_delay_seconds * (2 ** (attempt - 1)))
    # small jitter without random dep
    jitter = delay * 0.15
    time.sleep(max(0.0, delay - jitter))

