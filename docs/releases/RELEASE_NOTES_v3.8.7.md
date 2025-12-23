# Release Notes v3.8.7 — Reporting & Classification Fixes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.8.7_ES.md)

**Release Date:** 2025-12-23

## Summary

This hotfix improves report accuracy by fixing vulnerability source attribution and host status classification. It also enhances quiet-host HTTP identity probes and refines asset typing for media devices and Android-based hosts.

---

## Fixed

### Vulnerability Source Summary

Pipeline vulnerability sources now infer tool names from finding signals when explicit source fields are missing.

### Host Status Classification

Hosts with open ports are now marked `up` even when MAC/vendor data is present.

### Asset Type Detection

Chromecast/cast fingerprints are classified as `media`, Android OS hints map to `mobile`, and the topology default gateway is tagged as `router` for entity resolution.

### Quiet-Host HTTP Identity

Login pages without titles/headings now fall back to meta titles and common logo alt text to improve model detection.

---

## Upgrade

```bash
cd /path/to/RedAudit
git pull origin main
```

No configuration changes required.

---

[Back to README](../../README.md) | [Full Changelog](../../CHANGELOG.md)
