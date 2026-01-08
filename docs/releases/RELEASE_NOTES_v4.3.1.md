# RedAudit v4.3.1 - CI Maintenance Release

This is a maintenance release that addresses regression issues identified in the CI pipeline after the v4.3.0 release.

## Fixed

- **CI Test Regressions**: Resolved mock mismatches and architecture alignment for Wizard, Net Discovery, and Smart Scan Spec V1 tests.
  - Patched `_run_cmd_suppress_stderr` instead of `_run_cmd` in net discovery tests to correctly intercept calls.
  - Updated Deep Scan acceptance tests to verify the `deep_scan_suggested` flag, aligning with the decoupled deep scan architecture introduced in v4.2.
  - Fixed `StopIteration` errors in interactive wizard tests by ensuring mock inputs cover the full sequence of prompts.

These fixes ensure that the project's Continuous Integration tests pass reliably, validating the stability of the recent v4.3.0 feature additions.
