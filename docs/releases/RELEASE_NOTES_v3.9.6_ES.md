# Notas de Versión v3.9.6

**Fecha de Lanzamiento:** 2025-12-28

## Detección de Interfaces VPN

Esta versión introduce detección inteligente de gateways VPN usando tres heurísticas complementarias:

### Heurísticas de Detección

1. **Misma-MAC-que-Gateway**: Identifica IPs virtuales VPN detectando hosts que comparten la MAC del gateway pero tienen diferente IP (común en configuraciones VPN de FRITZ!Box, pfSense, Mikrotik)

2. **Puertos de Servicio VPN**: Reconoce endpoints VPN detectando puertos característicos:
   - 500, 4500 (IPSec/IKE)
   - 1194 (OpenVPN)
   - 51820 (WireGuard)

3. **Patrones de Hostname VPN**: Coincide con hostnames que contienen: `vpn`, `ipsec`, `wireguard`, `openvpn`, `tunnel`

### Cambios

- **entity_resolver.py**: Añadida lógica de clasificación VPN en `guess_asset_type()`
- **reporter.py**: Inyecta MAC/IP del gateway en registros de hosts para detección VPN
- **siem.py**: Añadido `vpn` a `ASSET_TYPE_TAGS` con tag SIEM `vpn-endpoint`

### Testing

10 tests unitarios cubriendo todos los escenarios de detección VPN.

---

**Changelog Completo**: [CHANGELOG.md](../../CHANGELOG.md)
