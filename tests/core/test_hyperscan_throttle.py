import pytest
from unittest.mock import patch
from redaudit.core.hyperscan import hyperscan_tcp_sweep


@pytest.mark.asyncio
async def test_hyperscan_adaptive_throttling():
    # Setup: 200 targets * 10 ports = 2000 probes
    targets = [f"192.168.1.{i}" for i in range(1, 201)]
    ports = range(80, 90)

    call_counter = {"count": 0}

    async def mock_behavior(ip, port, timeout, semaphore=None):
        call_counter["count"] += 1
        idx = call_counter["count"]

        # Scenario:
        # 0-1000 calls: 0% failure (Acceleration phase)
        # 1001-2000 calls: 10% failure (Congestion phase)

        if idx > 1000:
            if idx % 10 == 0:  # 10% failure
                return None

        return (ip, port)

    with patch("redaudit.core.hyperscan._tcp_connect", side_effect=mock_behavior):
        speeds = []

        def progress_tracker(completed, total, desc):
            # Parse speed from desc "TCP sweep ▼ (1250/s)" or similar
            # Expected format: "... (1234/s)"
            try:
                parts = desc.split("(")
                if len(parts) > 1:
                    speed_str = parts[-1].split("/s)")[0]
                    speeds.append(int(speed_str))
            except Exception:
                pass

        await hyperscan_tcp_sweep(
            targets=targets,
            ports=list(ports),
            batch_size=500,  # Start conservative
            progress_callback=progress_tracker,
        )

        print(f"Recorded speeds: {speeds}")

        assert len(speeds) > 0
        assert speeds[0] >= 500  # Initial speed might reflect first acceleration

        max_speed = max(speeds)
        assert max_speed > 500, "Should have accelerated beyond initial batch"

        # Verify throttling behavior
        # We expect the last speed to be lower than the max speed
        final_speed = speeds[-1]
        assert (
            final_speed < max_speed
        ), f"Should have throttled down. Max: {max_speed}, Final: {final_speed}"
