import asyncio
import itertools
import sys
import unittest
from unittest.mock import MagicMock, patch

from redaudit.core.hyperscan import SmartThrottle, hyperscan_tcp_sweep, _tcp_connect


class TestScalability(unittest.IsolatedAsyncioTestCase):

    def test_smart_throttle_generator_compatibility(self):
        """Verify SmartThrottle works with generator input."""
        throttler = SmartThrottle(initial_batch=500)

        # Simulate a generator of probes
        total_probes = 5000
        probes = (i for i in range(total_probes))

        consumed = 0
        batches = 0

        while True:
            batch_size = throttler.current_batch
            batch = list(itertools.islice(probes, batch_size))
            if not batch:
                break

            consumed += len(batch)
            batches += 1

            # Simulate stable network (no timeouts)
            throttler.update(len(batch), 0)

        self.assertEqual(consumed, total_probes)
        self.assertGreater(batches, 1)

    @patch("redaudit.core.hyperscan._tcp_connect")
    async def test_hyperscan_lazy_generation(self, mock_connect):
        """Verify hyperscan_tcp_sweep handles lazy iteration without materializing list."""
        mock_connect.return_value = None  # Simulate closed port

        # Mock huge input that would crash if materialized
        # 1000 targets * 1000 ports = 1M probes
        # Not truly huge for test speed, but conceptual check
        targets = [f"192.168.1.{i}" for i in range(100)]
        ports = list(range(100))

        # We can't easily measure RAM here, but we check execution completes
        results = await hyperscan_tcp_sweep(
            targets, ports, batch_size=100, timeout=0.01, mode="connect"
        )

        self.assertEqual(len(results), 100)
        self.assertEqual(mock_connect.call_count, 100 * 100)


if __name__ == "__main__":
    unittest.main()
