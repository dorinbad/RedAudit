## Description

Implements **Phase 4.0 MVP** (Authenticated Scanning), enabling SSH-based auditing and secure credential management.

> **Note**: This PR is part of a larger feature set (Phase 4). Will NOT merge until Phase 4 is complete.

### Key Changes

1. **Credentials Module** (`redaudit/core/credentials.py`)
    * `Credential` dataclass: Securely holds username, password, private key, domain.
    * `EnvironmentCredentialProvider`: Reads credentials from `REDAUDIT_*` env vars.
    * `KeyringCredentialProvider`: Uses OS keyring for secure local storage.
    * **Security**: Passwords redacted in `__repr__`, never stored in plaintext.

2. **SSH Scanner** (`redaudit/core/auth_ssh.py`)
    * Uses `paramiko` for SSH connections.
    * Supports Key-based and Password-based authentication.
    * Capabilities: `get_os_info`, `get_installed_packages`, `get_running_services`, `get_users`, `get_firewall_rules`.

3. **Dependencies**
    * Added optional `[auth]` group (`paramiko`, `keyring`).

### Verification

* **Tests**: 34 new unit tests (100% coverage of new modules).
* **Suite**: 1653 tests passed.
