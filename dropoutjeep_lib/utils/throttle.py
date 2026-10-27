"""Sliding-window rate throttle for SMTP provider limits.

Supports per-hour, per-day, and per-month windows in a single process.
For distributed deployments, replace the in-memory deque with Redis sorted
sets keyed by provider host.
"""

import time
from collections import deque


class SlidingWindowThrottle:
    """Throttle outbound sends against hourly/daily/monthly ceilings.

    The window is stored as a deque of Unix timestamps.  On each acquire()
    call, stale entries are pruned, and if the current window is full the
    caller sleeps until the oldest entry ages out.
    """

    def __init__(self, max_per_hour: int, max_per_day: int = None,
                 max_per_month: int = None):
        self.max_per_hour = max(1, int(max_per_hour or 1))
        self.max_per_day = max_per_day
        self.max_per_month = max_per_month
        self._hour_window: deque[float] = deque()
        self._day_window: deque[float] = deque()
        self._month_window: deque[float] = deque()

    def _prune(self, window: deque, ttl: float, now: float):
        while window and window[0] < now - ttl:
            window.popleft()

    def _wait_for(self, window: deque, limit: int, ttl: float, now: float):
        if limit is None or len(window) < limit:
            return
        sleep = window[0] - (now - ttl)
        if sleep > 0:
            time.sleep(sleep)

    def acquire(self):
        """Block until the current window has capacity, then record a send."""
        now = time.time()

        self._prune(self._hour_window, 3600, now)
        if self.max_per_day:
            self._prune(self._day_window, 86400, now)
        if self.max_per_month:
            self._prune(self._month_window, 30 * 86400, now)

        self._wait_for(self._hour_window, self.max_per_hour, 3600, now)
        if self.max_per_day:
            self._wait_for(self._day_window, self.max_per_day, 86400, now)
        if self.max_per_month:
            self._wait_for(self._month_window, self.max_per_month,
                           30 * 86400, now)

        now = time.time()
        self._hour_window.append(now)
        if self.max_per_day:
            self._day_window.append(now)
        if self.max_per_month:
            self._month_window.append(now)

    def current_counts(self):
        """Return current window counts (useful for dashboards)."""
        now = time.time()
        self._prune(self._hour_window, 3600, now)
        self._prune(self._day_window, 86400, now)
        self._prune(self._month_window, 30 * 86400, now)
        return {
            'hour': len(self._hour_window),
            'day': len(self._day_window) if self.max_per_day else None,
            'month': len(self._month_window) if self.max_per_month else None,
        }
