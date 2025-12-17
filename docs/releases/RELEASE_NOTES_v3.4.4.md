# Release Notes v3.4.4 - Defaults UX Hotfix

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.4.4_ES.md)

**Release Date**: 2025-12-17

## Overview

RedAudit v3.4.4 is a small hotfix that improves the interactive defaults workflow and adds a practical update note.

## Fixes

- **Defaults workflow**: Choosing "Use defaults and continue" now applies defaults correctly. Starting "immediately" no longer re-asks scan parameters, and can reuse saved targets when available.
- **Update note**: If the banner version does not refresh after updating, restart the terminal or run `hash -r` (zsh/bash).

## Upgrade Instructions

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

*RedAudit v3.4.4 - Smoother wizard defaults.*
