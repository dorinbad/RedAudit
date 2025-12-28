# RedAudit v3.9.4 Release Notes

[![Versión en Español](https://img.shields.io/badge/Español-blue)](./RELEASE_NOTES_v3.9.4_ES.md)

**Release Date**: 2025-12-28

## Highlights

This hotfix improves **net discovery parsing reliability**.

---

## 🐛 Bug Fixes

### DHCP Domain Hints With Prefixed Output

- Parses `Domain Name` and `Domain Search` even when Nmap prefixes lines with `|` or indentation.
- Recovers internal domain hints that were silently skipped before.

### NetBIOS Name Cleanup

- Trims trailing punctuation in NetBIOS names from nbstat output.
- Keeps asset inventories clean (e.g., `SERVER01` instead of `SERVER01,`).

---

## 📦 Installation

```bash
pip install --upgrade redaudit
# or
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.4
```

---

## 🔗 Links

- [Full Changelog](../../CHANGELOG.md)
- [Documentation](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
