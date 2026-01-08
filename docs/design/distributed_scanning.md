# Distributed Scanning Architecture (Concept)

## Overview

To scale RedAudit beyond single-node capabilities (handling >10k concurrent hosts), we propose a distributed architecture consisting of a **Control Plane** and multiple **Worker Nodes**.

## Components

### 1. Control Plane (Orchestrator)

- **Role**: API Server & Task Scheduler.
- **Tech Stack**: FastAPI + Redis (Queue).
- **Responsibilities**:
  - Receives scan requests (Targets, Profiles).
  - Splits targets into chunks (e.g., /24 subnets).
  - Pushes tasks to the Job Queue.
  - Aggregates results from workers into a central DB.

### 2. Worker Nodes (Agents)

- **Role**: Stateless execution units.
- **Tech Stack**: RedAudit CLI (headless) or Python Worker process.
- **Responsibilities**:
  - Pull task from Queue.
  - Execute `HyperScan` and `DeepScan`.
  - Stream results back to Result Queue/DB.

### 3. Data Store

- **Redis**: Hot queue and ephemeral state.
- **PostgreSQL/MongoDB**: Persistent storage for historical reports and asset inventory.

## Data Flow

1. User submits job: `redaudit scan --target 10.0.0.0/8 --distributed`.
2. Orchestrator splits /8 into 65,536 /24 tasks.
3. 50 Workers consume tasks in parallel.
4. Workers push findings to "Results" queue.
5. Aggregator process merges findings into the Report DB.

## Migration Path

1. Decouple `Auditor` logic from CLI (make it an importable library) - *Done*.
2. Implement `JSON Stream` output in `Reporter` (Phase 6.2 follow-up).
3. Build `redaudit-worker` wrapper.
4. Build `redaudit-server` wrapper.
