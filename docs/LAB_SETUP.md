# RedAudit Vulnerable Lab Setup

This guide explains how to set up the **RedAudit Testing Lab** using Docker. This environment mimics a real-world network with various vulnerable machines, SCADA systems, Active Directory, and IoT devices.

The lab corresponds to the credentials provided in `scripts/seed_keyring.py`.

## Prerequisites

- **Host OS**: Linux (Ubuntu/Debian recommended) or macOS
- **Docker**: Must be installed and running (`sudo systemctl start docker`)
- **Python 3**: For running the credential seeder

## Real-World Validation Note

> **Note**: This Docker lab is provided for **reproducibility** so users can safely test RedAudit's features.
>
> RedAudit is primarily developed and battle-tested in a **complex physical environment** featuring enterprise-grade routers, switches, hardware firewalls, physical IoT devices, and diverse operating systems. This Docker setup is a lightweight simulation of that environment designed for community use.

## Quick Start (Automated)

We provide a helper script to manage the entire lifecycle of the lab.

```bash
# 1. Install and provision the lab
sudo bash scripts/setup_lab.sh install

# 2. Check status (IPs and uptime)
sudo bash scripts/setup_lab.sh status
```

## Lab Management

| Action | Command | Description |
| :--- | :--- | :--- |
| **Start** | `sudo bash scripts/setup_lab.sh start` | Starts all stopped containers |
| **Stop** | `sudo bash scripts/setup_lab.sh stop` | Stops all running containers (frees resources) |
| **Remove** | `sudo bash scripts/setup_lab.sh remove` | DELETEs all containers and the network |
| **Status** | `sudo bash scripts/setup_lab.sh status` | Lists containers and pings IPs |

## Network Layout

- **Network**: `lab_seguridad`
- **Subnet**: `172.20.0.0/24`
- **Gateway**: `172.20.0.1`

### Targets

| IP | hostname | Role | Key Known Vulnerabilities |
| :--- | :--- | :--- | :--- |
| **.10** | `juiceshop` | Web (Node.js) | OWASP Top 10 |
| **.11** | `metasploitable` | Linux Legacy | SSH/SMB/Telnet weak creds |
| **.12** | `dvwa` | Web (PHP) | SQLi, XSS, Command Injection |
| **.13** | `webgoat` | Web (Java) | Training Vulnerabilities |
| **.15** | `bwapp` | Web | Buggy Web Application |
| **.20** | `target-ssh-lynis` | Ubuntu Hardened | SSH Compliance Testing |
| **.30** | `target-windows` | Windows Sim | SMB NULL Session |
| **.40** | `target-snmp` | SNMP v3 | Auth/Priv weak settings |
| **.50** | `openplc-scada` | SCADA | Modbus TCP (502) |
| **.51** | `conpot-ics` | ICS Honeypot | Siemens S7, Modbus |
| **.60** | `samba-ad` | Active Directory | LDAP, SMB, Kerberos (`REDAUDIT.LOCAL`) |
| **.70** | `iot-camera` | IoT Camera | Default credentials |
| **.71** | `iot-router` | IoT Router | Weak web administration |

## Scanning with RedAudit

Once the lab is running (`status` shows UP):

1. **Seed Credentials** (optional, one-time):

   ```bash
   python3 scripts/seed_keyring.py
   ```

2. **Run Scan**:

   ```bash
   sudo redaudit -t 172.20.0.0/24
   ```

3. **Wizard**: The wizard will detect the network and offer to load the saved credentials.
