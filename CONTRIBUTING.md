# Contributing to RedAudit

Thank you for your interest in contributing to RedAudit!

## Target Environment

RedAudit is designed specifically for:
*   **Operating Systems:** Kali Linux, Debian, Ubuntu, or other apt-based distributions.
*   **Privileges:** The tool must be run with `root` or `sudo` privileges to perform Nmap scans and other network operations.

Please ensure any code changes are compatible with this environment.

## How to Contribute

1.  **Fork the repository**.
2.  **Create a new branch** for your feature or bug fix (`git checkout -b feature/amazing-feature`).
3.  **Commit your changes** (`git commit -m 'Add some amazing feature'`).
4.  **Push to the branch** (`git push origin feature/amazing-feature`).
5.  **Open a Pull Request**.

## Reporting Bugs

If you find a bug, please open an issue describing:
*   Steps to reproduce.
*   Expected behavior.
*   Actual behavior.
*   Your environment (OS, Python version, etc.).

## Dependencies

Before submitting code, please ensure it works with the core dependencies. See [README.md](README.md#security-features) for the full list of required and recommended tools.

You can verify your environment and installation integrity by running:
```bash
bash redaudit_verify.sh
```

## Code Style

*   Keep the code clean and commented.
*   Follow PEP 8 for Python code where possible.
*   Shell scripts should be POSIX compliant where possible or clearly Bash-specific.
