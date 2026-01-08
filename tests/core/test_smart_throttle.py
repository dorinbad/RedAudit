import pytest
from redaudit.core.hyperscan import SmartThrottle


def test_smart_throttle_initialization():
    st = SmartThrottle(initial_batch=500, min_batch=100, max_batch=20000)
    assert st.current_batch == 500
    assert st.min_batch == 100
    assert st.max_batch == 20000


def test_smart_throttle_accelerate():
    st = SmartThrottle(initial_batch=500)
    # 0 timeouts out of 500 (0% failure) -> Should accelerate
    event = st.update(500, 0)
    assert event == "ACCELERATE"
    assert st.current_batch == 1000  # 500 + 500


def test_smart_throttle_congestion():
    st = SmartThrottle(initial_batch=1000)
    # 60 timeouts out of 1000 (6% failure) -> Should throttle (threshold is 5%)
    event = st.update(1000, 60)
    assert event == "THROTTLE_DOWN"
    assert st.current_batch == 500  # 1000 * 0.5


def test_smart_throttle_stable():
    st = SmartThrottle(initial_batch=1000)
    # 20 timeouts out of 1000 (2% failure) -> Stable (between 1% and 5%)
    event = st.update(1000, 20)
    assert event == "STABLE"
    assert st.current_batch == 1000


def test_smart_throttle_clamping():
    # Test Min Clamp
    st = SmartThrottle(initial_batch=100, min_batch=100)
    st.update(100, 50)  # 50% failure
    assert st.current_batch == 100  # Should not go below min

    # Test Max Clamp
    st = SmartThrottle(initial_batch=20000, max_batch=20000)
    st.update(20000, 0)  # 0% failure
    assert st.current_batch == 20000  # Should not go above max
