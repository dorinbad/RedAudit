# Technical Specification: Smart-Throttle (Adaptive Congestion Control)

**Phase:** 6 (Enterprise Scalability)
**Status:** Planned
**Target Component:** `redaudit/core/hyperscan.py`

## 1. Problem Definition

Current `HyperScan` uses a fixed `batch_size` (default 3000).

- **Scenario A (SOHO/VPN):** 3000 pps causes packet loss, router CPU spikes, and false negatives (timeouts).
- **Scenario B (Data Center):** 3000 pps is inefficient on 10Gbps links; capable of handling 20k+ pps.

## 2. Proposed Solution: AIMD Algorithm

Implement an **Additive Increase, Multiplicative Decrease (AIMD)** control loop similar to TCP congestion control.

### 2.1 Core Algorithm

- **Start:** `batch_size = 500` (Conservative Slow Start)
- **Metric:** Round-Trip Time (RTT) and Timeout Rate (Error %).
- **Loop (per batch):**
  1. Measure % of targets in batch that timed out.
  2. Measure average completion time of batch.
  3. **Decision:**
     - **Good Conditions** (Timeouts < 1%): Increase `batch_size` linearly (`+500`).
     - **Congestion Detected** (Timeouts > 5%): Decrease `batch_size` multiplicatively (`* 0.5`).
     - **Recovery:** Minimum `batch_size` clamp (e.g., 100).

### 2.2 Pseudocode Implementation

```python
class SmartThrottle:
    def __init__(self):
        self.current_batch = 500
        self.min_batch = 100
        self.max_batch = 20000
        self.threshold_timeout = 0.05  # 5%

    def update(self, sent_count, timeout_count, duration):
        failure_rate = timeout_count / sent_count

        if failure_rate > self.threshold_timeout:
            # CONGESTION: Cut speed in half
            self.current_batch = max(self.min_batch, int(self.current_batch * 0.5))
            return "THROTTLE_DOWN"
        else:
            # CLEAR: Linear increase
            self.current_batch = min(self.max_batch, self.current_batch + 500)
            return "ACCELERATE"
```

## 3. Integration Plan

1. **Modify `asyncio` Loop:** `hyperscan_tcp_sweep` checks `SmartThrottle` between chunks.
2. **UI Feedback:** Show dynamic speed changes in progress bar (e.g., `[Speed: 1200 pps (▼ Throttled)]`).
3. **Optimizations:**
   - **Zero-Copy Research:** Evaluate strict `asyncio` limits before resorting to raw sockets.
   - **Banner Grabbing:** Add opportunistic `100ms` peek on connect for service ID (Hybrid Mode).

## 4. Success Metrics

- **Reliability:** < 1% difference in open ports detected between "Slow Scan" (T3) and "Smart-Throttle" on unstable networks.
- **Speed:** > 50% reduction in scan time on stable Gigabit networks compared to static default.
