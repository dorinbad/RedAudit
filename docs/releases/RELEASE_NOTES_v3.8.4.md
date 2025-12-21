# Release Notes v3.8.4 — Color Consistency Fix

**Release Date:** 2025-12-21

## Summary

This patch release fixes a visual bug where `[INFO]` status messages appeared without their intended blue color when the Rich progress bar was active.

---

## Fixed

### Status Colors During Progress

When Rich Progress was active (during host scanning phases), status messages printed via `print_status()` could lose their ANSI color formatting. This occurred because Rich's output handling interfered with direct `print()` calls using raw ANSI codes.

**Solution:** When `_ui_progress_active` is true, the `print_status()` method now uses Rich's `console.print()` with proper markup:

| Status | Rich Style |
|--------|------------|
| INFO | `bright_blue` |
| OK | `green` |
| WARN | `yellow` |
| FAIL | `red` |

This ensures consistent color display regardless of progress bar state.

---

## Technical Details

- **File modified:** `redaudit/core/auditor.py`
- **Method:** `InteractiveNetworkAuditor.print_status()`
- **Fallback:** Standard ANSI codes are still used when progress is not active or Rich is unavailable

---

## Upgrade

```bash
cd /path/to/RedAudit
git pull origin main
```

No configuration changes required.

---

[Back to README](../../README.md) | [Full Changelog](../../CHANGELOG.md)
