# RedAudit v2.6.0

## Modular Architecture & CI/CD Release

### Highlights

- **Modular Architecture**: Refactored monolithic script into organized Python package (8 modules)
- **CI/CD Pipeline**: GitHub Actions for automated testing on Python 3.9-3.12
- **Test Coverage**: Expanded to 34 automated tests

### New Features

- **Package Structure**: `redaudit/core/` and `redaudit/utils/` modules
- **Alternative Invocation**: `python -m redaudit` support
- **Named Constants**: All magic numbers replaced with descriptive constants
- **New Test Suites**: `test_network.py`, `test_reporter.py`

### Installation

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

### CLI Options

- `--target, -t`: Target network(s) in CIDR notation
- `--mode, -m`: fast/normal/full (default: normal)
- `--threads, -j`: 1-16 (default: 6)
- `--rate-limit`: Delay between hosts in seconds
- `--encrypt, -e`: Encrypt reports
- `--output, -o`: Output directory
- `--max-hosts`: Limit number of hosts
- `--yes, -y`: Skip legal warning
- `--lang`: Language (en/es)

### Package Structure

```text
redaudit/
├── core/           # Core functionality
│   ├── auditor.py  # Main orchestrator
│   ├── crypto.py   # Encryption (PBKDF2, Fernet)
│   ├── network.py  # Network detection
│   ├── reporter.py # Report generation
│   └── scanner.py  # Scanning logic
└── utils/          # Utilities
    ├── constants.py
    └── i18n.py
```

### Testing

- 34 automated tests passing
- CI/CD via GitHub Actions
- Codecov integration

### Documentation

Complete bilingual documentation (English/Spanish):

- README.md / README_ES.md
- MANUAL_EN.md / MANUAL_ES.md
- USAGE.md / USAGE_ES.md
- SECURITY.md, TROUBLESHOOTING.md, REPORT_SCHEMA.md

### Backward Compatibility

- Original `redaudit.py` preserved as wrapper
- All existing scripts continue to work

### Links

- **Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Documentation**: [docs/](docs/)
- **Security Specs**: [docs/SECURITY.md](docs/SECURITY.md)
- **License**: GPLv3
