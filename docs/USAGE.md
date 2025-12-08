<div align="center">

# 🛠️ RedAudit Usage Guide

[![Language](https://img.shields.io/badge/Language-English-blue?style=for-the-badge)](USAGE.md)
[![Type](https://img.shields.io/badge/Type-Guide-orange?style=for-the-badge)](MANUAL_EN.md)

</div>

---

> **Tip**: For a deep technical dive (Threads, Encryption internals, etc.), check the [Professional User Manual](MANUAL_EN.md).



## Installation
RedAudit is designed for Kali Linux or Debian-based systems.

1. **Install & Update**:
   ```bash
   sudo bash redaudit_install.sh
   # Or for non-interactive mode:
   sudo bash redaudit_install.sh -y
   ```
   This installs dependencies (`nmap`, `python3-cryptography`, etc.) and creates the alias.

2. **Reload Shell**:
   ```bash
   source ~/.bashrc  # for Bash
   # OR
   source ~/.zshrc   # for Zsh
   ```

3. **Run**:
   ```bash
   # Interactive mode
   redaudit
   
   # Non-interactive mode (v2.5)
   sudo redaudit --target 192.168.1.0/24 --mode normal
   ```

## Workflow

### 1. Configuration

#### Interactive Mode
The tool will prompt you for:
- **Target Network**: Auto-detected interfaces or manual CIDR.
- **Scan Mode**: Normal (Discovery+Top Ports), Fast, or Full.
- **Threads**: Number of concurrent workers.
- **Rate Limit**: Optional delay (seconds) between hosts for stealth.
- **Encryption**: Optional password protection for reports.
- **Output Directory**: Defaults to `~/RedAuditReports`.

#### Non-Interactive Mode (v2.5)
All configuration via command-line arguments:
```bash
sudo redaudit \
  --target 192.168.1.0/24 \
  --mode full \
  --threads 8 \
  --rate-limit 1 \
  --encrypt \
  --output /custom/path \
  --max-hosts 100
```

### 2. Execution Phases
- **Discovery**: fast ping scan to find live hosts.
- **Port Scan**: specific nmap scan per host.
- **Vulnerability Scan**: checks web services (http/https) against `whatweb` / `nikto` (if full mode).

### 3. Reports & Encryption
Reports are saved with a timestamp `redaudit_YYYYMMDD_HHMMSS`.
- **Plain**: `.json` and `.txt`.
- **Encrypted**: `.json.enc`, `.txt.enc`, and `.salt`.

To decrypt results:
```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```
This will generate `.decrypted` files (or restore original extension) after password verification.

### 4. Logging
Debug logs are stored in `~/.redaudit/logs/`. Check these files if the scan fails or behaves unexpectedly.

## Performance & Stealth
### Rate Limiting
RedAudit allows you to set a delay (in seconds) between scanning hosts.
- **0s (Default)**: Maximum speed. Best for internal audits where noise is not a concern.
- **1-5s**: Moderate stealth. Reduces the chance of triggering simple rate-limit firewalls.
- **>10s**: High stealth. Significantly slows down the audit but minimizes network congestion and detection risk.

**Note on Heartbeat**: If you set a very high delay (e.g., 60s) with many threads, the scan might seem "frozen". Check the "Active hosts" log or the heartbeat status.

### CLI Execution Markers
RedAudit v2.5 strictly informs you about the commands being executed:
- **`[nmap] 192.168.x.x → nmap ...`**: Standard port scan.
- **`[deep] 192.168.x.x → combined ...`**: Deep Identity Scan execution (expect 90-140s duration).

### Adaptive Deep Scan & Traffic Capture
RedAudit automatically attempts an "Adaptive Deep Scan" on hosts that:
1.  **Have >8 open ports**
2.  **Have suspicious services** (socks, proxy, vpn, tor, nagios, etc.)
3.  **Have very few ports (<=3)**
4.  **Have open ports but no version information detected**
 
- **Adaptive Strategy**: Runs a 2-phase scan (TCP aggressive first, then UDP/OS fallback only if Phase 1 didn't find MAC/OS identity) to fingerprint complex hosts.
- **Traffic Capture**: As part of Deep Scan, if `tcpdump` is available, the tool captures a **50-packet snippet** (max 15s) from the host's traffic.
    - Saves `.pcap` files in your report directory.
    - If `tshark` is installed, a text summary of protocols is included in the JSON report.
    - *Defense*: The capture duration is strictly capped to prevent hanging.

---

RedAudit is licensed under **GPLv3**. See [LICENSE](../LICENSE) for details.


