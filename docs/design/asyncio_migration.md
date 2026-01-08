# AsyncIO Full Migration Investigation (Phase 6.4)

## Status

**Investigated**: Yes
**Feasibility**: High
**Effort**: High (Major Refactor)

## Current Blocking Hotspots

RedAudit currently relies on `threading.ThreadPoolExecutor` for concurrency. The following synchronous patterns block the main thread or worker threads:

1. **Subprocess Execution (`subprocess.run`)**:
   - `redaudit/core/command_runner.py`: Core wrapper for all external tools.
   - `redaudit/core/net_discovery.py`: Direct calls for arp-scan/ping.
   - `redaudit/core/osquery.py`: Direct osqueryi calls.

2. **HTTP Requests (`requests` lib)**:
   - `redaudit/utils/oui_lookup.py`: Vendor API lookups.
   - `redaudit/core/nvd.py`: NIST API calls.
   - `redaudit/core/updater.py`: GitHub release checks.

3. **Sleeps (`time.sleep`)**:
   - Widespread usage for retries and rate limiting (`auditor_scan.py`, `nvd.py`).

## Migration Strategy

### 1. Core Async Primitives

- **AsyncCommandRunner**: Replace `subprocess.run` with `asyncio.create_subprocess_exec`.
- **HTTP Client**: Replace `requests` with `aiohttp` or `httpx`.

### 2. Orchestration Refactor

- Convert `Auditor.run()` to an `async` entry point.
- Replace `ThreadPoolExecutor` usage in `scan_hosts_concurrent` with `asyncio.gather()` or `TaskGroup` (Python 3.11+).

### 3. Benefits

- **Higher Density**: Handle 10k+ concurrent connections (vs ~50 threads).
- **Responsiveness**: UI updates won't freeze during blocking I/O.
- **Resource Usage**: Lower memory/CPU overhead per connection.

## Recommendation

Defer full migration to **RedAudit v5.0**. The current hybrid model (AsyncIO for HyperScan + Threads for DeepScan) is sufficient for current Enterprise targets (<50k hosts).
