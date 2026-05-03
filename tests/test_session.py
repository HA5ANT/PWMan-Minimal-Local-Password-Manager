import time
import pytest
from src.session import Session
from src.models import MasterKey

def test_session_init():
    s = Session()
    assert s.db_path is None
    assert s.master_key is None
    assert s.timeout_seconds == 120

def test_session_refresh():
    s = Session()
    old_time = s.last_activity
    time.sleep(0.1)
    s.refresh()
    assert s.last_activity > old_time

def test_session_check_timeout():
    s = Session()
    s.timeout_seconds = 1
    s.master_key = MasterKey(b"fake_key")
    s.last_activity = time.time() - 2
    assert s.check_timeout() is True
    assert s.master_key is None

def test_session_get_remaining_time():
    s = Session()
    s.timeout_seconds = 60
    s.master_key = MasterKey(b"fake_key")
    s.last_activity = time.time()
    res = s.get_remaining_time()
    assert res in ["1:00", "0:59"]
    
    s.last_activity = time.time() - 30
    res = s.get_remaining_time()
    assert res in ["0:30", "0:29"]

def test_session_on_timeout_callback():
    s = Session()
    s.timeout_seconds = 0.1
    s.master_key = MasterKey(b"fake_key")
    s.last_activity = time.time() - 1
    
    timeout_called = False
    def on_timeout():
        nonlocal timeout_called
        timeout_called = True
    
    s.on_timeout = on_timeout
    s.start_watchdog()
    time.sleep(0.5)
    s.stop_watchdog()
    
    assert timeout_called is True
    assert s.master_key is None
