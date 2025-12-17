# RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](README.md)

Auditoría y hardening de red para sistemas Kali/Debian — asistente interactivo + salida CLI pensada para CI.

![Version](https://img.shields.io/github/v/tag/dorinbadea/RedAudit?sort=semver&style=flat-square)
![CI/CD](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg?style=flat-square)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![Kali](https://img.shields.io/badge/Kali-rolling-557C94?style=flat-square)
![Debian](https://img.shields.io/badge/Debian-11%2B-A81D33?style=flat-square)
![License](https://img.shields.io/badge/license-GPLv3-green?style=flat-square)

<details>
<summary>Banner</summary>

```text
 ____          _    _             _ _ _
|  _ \ ___  __| |  / \  _   _  __| (_) |_
| |_) / _ \/ _` | / _ \| | | |/ _` | | __|
|  _ <  __/ (_| |/ ___ \ |_| | (_| | | |_
|_| \_\___|\__,_|/_/   \_\__,_|\__,_|_|\__|
     Herramienta Interactiva de Auditoría de Red
```

</details>

## Inicio rápido

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

Ejecuta el asistente interactivo:

```bash
sudo redaudit
```

O ejecuta en modo no interactivo:

```bash
sudo redaudit --target 192.168.1.0/24 --mode normal --yes
```

## Documentación

- Uso (flags + ejemplos): `docs/es/USAGE.md`
- Manual (instalación, conceptos, salidas): `docs/es/MANUAL.md`
- Esquema de reportes: `docs/es/REPORT_SCHEMA.md`
- Modelo de seguridad y notas del updater: `docs/es/SECURITY.md`
- Troubleshooting: `docs/es/TROUBLESHOOTING.md`
- Registro de cambios: `CHANGELOG_ES.md`

## Qué obtienes

RedAudit orquesta herramientas estándar (p. ej. `nmap`, `whatweb`, `nikto`, `testssl.sh`) en un pipeline consistente y genera artefactos listos para reporting e ingesta SIEM.

Capacidades clave:

- Deep scan adaptativo de identidad (TCP + UDP) con capturas PCAP best-effort
- Descubrimiento de topología y descubrimiento broadcast/L2 opcionales (`--topology`, `--net-discovery`)
- Recon Red Team opt-in dentro de net discovery (`--redteam`, guarded; requiere root)
- Soporte completo de `--dry-run` (no se ejecutan comandos externos; se imprimen)
- Dashboard HTML + exportaciones JSONL + playbooks (omitidos si el cifrado está activado)

## Salidas

Cada ejecución crea una carpeta con sello temporal (por defecto: `~/Documents/RedAuditReports/RedAudit_YYYY-MM-DD_HH-MM-SS/`) con:

- `redaudit_<timestamp>.json` y `redaudit_<timestamp>.txt` (o `.enc` + `.salt` si hay cifrado)
- `report.html` (dashboard HTML, si el cifrado está desactivado)
- `findings.jsonl`, `assets.jsonl`, `summary.json` (exportaciones planas para SIEM/IA, si el cifrado está desactivado)
- `run_manifest.json` (métricas + lista de artefactos, si el cifrado está desactivado)
- `playbooks/` (guías de remediación en Markdown, si el cifrado está desactivado)
- `traffic_*.pcap` (micro-capturas best-effort durante deep scan si aplica)

## Seguridad y requisitos

- Ejecuta con `sudo` para funcionalidad completa (raw sockets, OS detection, `tcpdump`/capturas). Existe modo limitado: `--allow-non-root`.
- Las funciones Red Team son opt-in y solo para auditorías autorizadas.
- Si actualizas y el banner/versión no se refresca, reinicia el terminal o ejecuta `hash -r`.

## Contribuir

Ver `.github/CONTRIBUTING.md`.

## Licencia

GNU GPLv3. Ver `LICENSE`.
