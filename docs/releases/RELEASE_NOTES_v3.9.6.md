# Release Notes v3.9.6

**Release Date:** 2025-12-28

## VPN Interface Detection

This release introduces intelligent VPN gateway detection using three complementary heuristics:

### Detection Heuristics

1. **Same-MAC-as-Gateway**: Identifies VPN virtual IPs by detecting hosts that share the gateway's MAC address but have a different IP (common in FRITZ!Box, pfSense, Mikrotik VPN configurations)

2. **VPN Service Ports**: Recognizes VPN endpoints by detecting characteristic ports:
   - 500, 4500 (IPSec/IKE)
   - 1194 (OpenVPN)
   - 51820 (WireGuard)

3. **VPN Hostname Patterns**: Matches hostnames containing: `vpn`, `ipsec`, `wireguard`, `openvpn`, `tunnel`

### Changes

- **entity_resolver.py**: Added VPN classification logic in `guess_asset_type()`
- **reporter.py**: Injects gateway MAC/IP into host records for VPN detection
- **siem.py**: Added `vpn` to `ASSET_TYPE_TAGS` with `vpn-endpoint` SIEM tag

### Testing

10 unit tests covering all VPN detection scenarios.

---

**Full Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
