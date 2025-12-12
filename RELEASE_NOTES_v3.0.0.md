# RedAudit v3.0.0 Release Notes

**Release Date**: December 2025

RedAudit v3.0.0 is a **major feature release** introducing six significant capabilities that enhance network auditing for complex environments.

## Highlights

| Feature | Description |
|:---|:---|
| **IPv6 Support** | Full scanning for IPv6 networks with automatic Nmap `-6` flag |
| **CVE Correlation** | NIST NVD API 2.0 integration with 7-day cache |
| **Differential Analysis** | Compare two JSON reports to track network changes |
| **Proxy Chains** | SOCKS5 pivoting via proxychains wrapper |
| **Magic Byte Validation** | File signature verification for false positive reduction |
| **Enhanced Auto-Update** | Git clone approach with verification |

---

## New Features

### IPv6 Support

Scan IPv6 networks with the same capabilities as IPv4:

```bash
sudo redaudit --target "2001:db8::/64" --ipv6 --mode normal
```

- Automatic `-6` flag in Nmap commands
- IPv6 network detection via netifaces
- Link-local address handling

### CVE Correlation (NVD)

Enrich scan results with vulnerability intelligence:

```bash
sudo redaudit --target 192.168.1.0/24 --cve-lookup --nvd-key YOUR_KEY
```

- CPE 2.3 matching for accurate lookups
- CVSS scores and severity levels
- 7-day persistent cache for offline use
- Respects NVD rate limits (0.6s with key, 6s without)

### Differential Analysis

Track network changes over time:

```bash
sudo redaudit --diff scan_monday.json scan_friday.json
```

- Identifies new/removed hosts and ports
- Highlights vulnerability changes
- Generates both JSON and Markdown output

### Proxy Chains (SOCKS5)

Pivot through SOCKS5 proxies for internal networks:

```bash
sudo redaudit --target 10.0.0.0/24 --proxy socks5://pivot:1080
```

- Proxychains wrapper integration
- Connection testing before scan
- Supports authentication

### Magic Byte Validation

Reduced false positives in Smart-Check module:

- Downloads first 512 bytes of responses
- Verifies file signatures (tar: `ustar`, gzip: `1f8b`, zip: `PK`)
- Eliminates embedded server Soft-404s

### Enhanced Auto-Update

More reliable update mechanism:

- Fresh `git clone` to temporary directory
- Runs install script with your language preference
- Copies to `~/RedAudit` with all documentation
- Verifies installation integrity

---

## New CLI Flags

| Flag | Description |
|:---|:---|
| `--ipv6` | Enable IPv6-only scanning mode |
| `--proxy URL` | SOCKS5 proxy for pivoting |
| `--diff OLD NEW` | Compare two JSON reports |
| `--cve-lookup` | Enable CVE correlation via NVD API |
| `--nvd-key KEY` | NVD API key for faster rate limits |

---

## New Modules

| Module | Purpose |
|:---|:---|
| `nvd.py` | NVD API integration with CPE matching |
| `diff.py` | Differential analysis engine |
| `proxy.py` | SOCKS5 proxy manager |

---

## Upgrade Instructions

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

Or let the auto-update system handle it at next startup.

---

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

## License

GPLv3 - See [LICENSE](LICENSE) for details.
