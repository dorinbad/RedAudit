<div align="center">

# 🔧 RedAudit Troubleshooting Guide

[![Type](https://img.shields.io/badge/Type-Support-orange?style=for-the-badge)](MANUAL_EN.md)
[![Issues](https://img.shields.io/badge/Report-Bug-red?style=for-the-badge&logo=github)](https://github.com/dorinbadea/RedAudit/issues)

</div>

---

## Common Issues

### 1. `Permission denied` or "Root privileges required"
**Symptom**: The script exits immediately with an error about root.
**Solution**: RedAudit requires low-level network access (nmap, tcpdump).
- Always run with: `sudo redaudit` or `sudo bash redaudit_install.sh`.

### 2. `nmap: command not found`
**Symptom**: The scan fails saying nmap binary is missing.
**Solution**: The installer should have handled this, but you can fix it manually:
```bash
sudo apt update && sudo apt install -y nmap
```

### 3. Decryption Failed
**Symptom**: `redaudit_decrypt.py` says "Mac check failed" or "Invalid token" or "Decryption failed".
**Causes**:
- **Wrong Password**: Ensure you use the exact password set during the scan.
- **Missing Salt**: The `.salt` file MUST be in the same folder as the `.enc` file.
- **File Corruption**: If you transferred the files, ensure binary mode was used.

### 4. Heartbeat Warning ("No output for X seconds")
**Symptom**: You see yellow warnings about "Activity Monitor" during a scan.
**Explanation**: This is normal during heavy Nmap scans (especially `-p-` or `-sV` on slow hosts).
**Action**: Wait. If it exceeds 300s (5 mins) with no output, verify the target host is not blocking you completely (firewall drop).
**Note**: The heartbeat message "Fail" now clarifies that Nmap is still running. Do not abort immediately; deep scans on filtered hosts can take time.

### 5. "Scans seem to hang" / Slow progress
**Symptom**: The tool pauses for 1-2 minutes on a single host.
**Explanation**: RedAudit v2.5 performs **Deep Identity Scans** on complex hosts (combined TCP/UDP/OS fingerprinting).
- **Duration**: These scans can legitimately take **90–150 seconds** per host.
- **Why**: Essential for identifying IoT boxes, firewalls, or filtered servers that hide their OS.
- **Check**: Look for the `[deep]` marker in the CLI output.

### 6. "Cryptography not available" warning
**Symptom**: You see a warning about `python3-cryptography` not being available.
**Explanation**: Encryption feature requires `python3-cryptography`. In v2.5, the tool gracefully degrades if it's missing.
**Solution**: 
```bash
sudo apt install python3-cryptography
```
**Note**: In v2.5, if cryptography is unavailable, encryption options are automatically disabled. No password prompts will appear.

### 7. Non-interactive mode errors
**Symptom**: `--target` argument not working or "Error: --target is required".
**Solution**: 
- Ensure you provide `--target` with a valid CIDR (e.g., `--target 192.168.1.0/24`)
- Multiple targets: `--target "192.168.1.0/24,10.0.0.0/24"`
- Check CIDR format is correct
- See `redaudit --help` for all available options

**Symptom**: The script refuses to start.
**Solution**: Run the installer again to fix missing python libraries:
```bash
sudo bash redaudit_install.sh -y
```

RedAudit and this troubleshooting guide are part of a GPLv3-licensed project. See [LICENSE](../LICENSE).
