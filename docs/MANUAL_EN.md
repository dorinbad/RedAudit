# RedAudit Installation Manual v2.3

**Role:** Pentester / Senior Programmer

## 1. Prerequisites

**Target System:**
*   Kali Linux (or similar Debian-based distro)
*   User with `sudo` privileges
*   Internet connection for package installation

**Packages used** (installed automatically by the script, but listed here for reference):

```bash
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-nmap \
  curl wget openssl nmap tcpdump tshark whois bind9-dnsutils \
  whatweb nikto
```

> **Note:** `whatweb`, `nikto`, and `nmap` are the core requirements for RedAudit. The others are utilities that the script prepares for future modules (tcpdump/tshark/WHOIS/DNS/etc).

*   **Automatic Deep Scan:** The tool automatically detects "quiet" or suspicious hosts and launches a deep scan (`-A -p- -sV`) including packet capture to identify firewalls or hidden services.

---

## 2. Prepare Working Directory

We use a standard directory for tools:

```bash
mkdir -p ~/security_tools
cd ~/security_tools
```

---

## 3. Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.  Run the installer:
    ```bash
    chmod +x redaudit_install.sh
    sudo ./redaudit_install.sh
    
    # Or for non-interactive installation:
    # sudo ./redaudit_install.sh -y
    ```

The installer will:
1.  Offer to install recommended network utilities.
2.  Install RedAudit to `/usr/local/bin/redaudit`.
3.  Set up the necessary shell alias.

---

## 5. Activate the Alias

After installation:

```bash
source ~/.bashrc
```

From now on, in any terminal as your normal user:

```bash
redaudit
```

---

## 6. Quick Verification

Useful commands to check everything is in place:

```bash
# Where is the binary?
which redaudit
# → should point to /usr/local/bin/redaudit (via alias)

# Check binary permissions
ls -l /usr/local/bin/redaudit

# Confirm alias
grep "alias redaudit" ~/.bashrc
```

---

## 7. Updating RedAudit

To update the code (e.g., from 2.3 to 2.4):
1.  Edit the installer `redaudit_install.sh` with the new code.
2.  Run it again:
    ```bash
    sudo ./redaudit_install.sh
    source ~/.bashrc  # Or ~/.zshrc
    ```

The binary `/usr/local/bin/redaudit` will be overwritten with the new version.

---

## 8. Uninstallation

To remove the binary and alias:

```bash
sudo rm -f /usr/local/bin/redaudit
sed -i '/alias redaudit=/d' ~/.bashrc  # Or ~/.zshrc
source ~/.bashrc  # Or ~/.zshrc
```
