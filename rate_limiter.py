from datetime import datetime, timedelta
from typing import Dict, Tuple

class RateLimiter:
    """
    A simple in-memory rate limiter for brute force protection.
    
    In production, use a distributed cache like Redis for rate limiting.
    """
    
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts: Dict[str, Tuple[int, datetime]] = {}
    
    def increment(self, key: str) -> None:
        """Increment the attempt counter for a key."""
        now = datetime.utcnow()
        
        if key in self.attempts:
            count, timestamp = self.attempts[key]
            
            # Reset if window has passed
            if now - timestamp > timedelta(seconds=self.window_seconds):
                self.attempts[key] = (1, now)
            else:
                self.attempts[key] = (count + 1, timestamp)
        else:
            self.attempts[key] = (1, now)
    
    def is_rate_limited(self, key: str) -> bool:
        """Check if a key is rate limited."""
        if key not in self.attempts:
            return False
        
        count, timestamp = self.attempts[key]
        now = datetime.utcnow()
        
        # Reset if window has passed
        if now - timestamp > timedelta(seconds=self.window_seconds):
            self.attempts[key] = (0, now)
            return False
        
        return count >= self.max_attempts
    
    def get_time_remaining(self, key: str) -> int:
        """Get the time remaining (in minutes) for a rate limit."""
        if key not in self.attempts:
            return 0
        
        count, timestamp = self.attempts[key]
        now = datetime.utcnow()
        
        # If not rate limited, return 0
        if count < self.max_attempts or now - timestamp > timedelta(seconds=self.window_seconds):
            return 0
        
        # Calculate time remaining until window expires
        window_end = timestamp + timedelta(seconds=self.window_seconds)
        remaining_seconds = (window_end - now).total_seconds()
        
        # Return minutes, minimum 1
        return max(1, int(remaining_seconds / 60))
    
    def reset(self, key: str) -> None:
        """Reset the counter for a key."""
        if key in self.attempts:
            self.attempts.pop(key)