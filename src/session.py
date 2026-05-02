import time
from typing import Optional
from .models import MasterKey

class Session:
    """Track active vault state and auto-lock timer during interactive session."""
    
    def __init__(self):
        self.db_path: Optional[str] = None
        self.master_key: Optional[MasterKey] = None
        self.timeout_seconds: int = 120  # Default 2 minutes
        self.last_activity: float = time.time()
        
    def is_active(self) -> bool:
        """Check if a vault is currently loaded."""
        return self.db_path is not None

    def check_timeout(self) -> bool:
        """
        Check if the session has timed out. 
        If timed out, clear the master key and return True.
        """
        if self.master_key and (time.time() - self.last_activity > self.timeout_seconds):
            self.master_key = None
            return True
        return False

    def refresh(self):
        """Update the last activity timestamp."""
        self.last_activity = time.time()

    def get_remaining_time(self) -> str:
        """Return formatted M:SS of remaining time."""
        if not self.master_key: return "0:00"
        remaining = self.timeout_seconds - (time.time() - self.last_activity)
        if remaining <= 0: return "0:00"
        m, s = divmod(int(remaining), 60)
        return f"{m}:{s:02}"

    def clear(self):
        """Wipe session state entirely."""
        self.db_path = None
        self.master_key = None
        self.last_activity = time.time()

# Global session instance
session = Session()
