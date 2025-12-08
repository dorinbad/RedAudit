<div align="center">

# 🚀 Mejoras y Roadmap de RedAudit

[![Status](https://img.shields.io/badge/Status-Active_Maintenance-success?style=for-the-badge&logo=git)](https://github.com/dorinbadea/RedAudit)
[![Version](https://img.shields.io/badge/Roadmap-v2.6_to_v4.0-blue?style=for-the-badge)](https://github.com/dorinbadea/RedAudit/milestones)
[![Last Update](https://img.shields.io/badge/Last_Update-Dec_2025-lightgrey?style=for-the-badge)](https://github.com/dorinbadea/RedAudit/commits)

</div>

<div align="center">

**📌 Nota Importante**  
*Este roadmap es una guía de desarrollo, no un compromiso contractual. Las prioridades pueden cambiar según feedback de la comunidad, hallazgos de seguridad o recursos disponibles.*

</div>

---

## 📋 Índice

1. [Estado Actual (v2.5)](#-estado-actual-y-puntos-fuertes-v25)
2. [Sugerencias de Mejora](#-sugerencias-de-mejora-detalladas)
3. [Roadmap Estratégico](#-roadmap-estratégico)
4. [Ideas Descartadas](#-ideas-descartadas)
5. [Contribuir](#-quieres-participar)

---

## 🎯 Estado Actual y Puntos Fuertes (v2.5)

| Categoría | Características Destacadas |
| :--- | :--- |
| **🏗️ Arquitectura** | Diseño modular con `ThreadPoolExecutor`, sistema de heartbeat y reportes duales (JSON/TXT). |
| **🛡️ Seguridad** | Encriptación **AES-128 (Fernet)** + PBKDF2 (480k its), sanitización estricta y permisos `0o600`. |
| **💻 UX** | Modos Interactivo/No-Interactivo (CLI), instalador automatizado y soporte **EN/ES**. |
| **⚠️ Evasión** | Rate limiting configurable y scans adaptativos en 2 fases. |

---

## 💡 Sugerencias de Mejora Detalladas

### 1. Testing & CI/CD
Establecer una suite de pruebas robusta y pipelines de integración continua.

```bash
tests/
├── test_input_validation.py  # Tests de sanitización (Existente)
├── test_encryption.py        # Tests de cifrado/descifrado (Existente)
├── test_network_discovery.py # Mocking de interfaces
└── test_scan_modes.py        # Mocking de Nmap
```
> **Acción**: Crear `.github/workflows/tests.yml` para ejecutar estos tests en cada PR.

### 2. Configuración Persistente
Eliminar valores hardcoded y permitir configuración de usuario en `~/.redaudit/config.yaml`.

```yaml
default:
  threads: 6
  rate_limit: 0
  output_dir: ~/RedAuditReports
  encrypt_by_default: false
  language: es
```

### 3. Nuevos Formatos de Exportación
*   📄 **PDF**: Reportes ejecutivos con gráficos de topología.
*   📊 **CSV**: Para importación en Excel/Pandas.
*   🌐 **HTML**: Reportes interactivos con tablas y búsqueda.

### 4. Integración de CVEs
Enriquecer los resultados consultando bases de datos de vulnerabilidades.

```python
if service_version:
    cves = query_cve_database(service, version)
    host['potential_vulnerabilities'] = cves
```

### 5. Comparación de Auditorías (Diffing)
Detectar cambios entre dos escaneos para identificar desviaciones.

```bash
redaudit --compare scan_ayer.json scan_hoy.json
# [!] Nuevo puerto detectado: 3306/tcp en 192.168.1.50
```

---

## 🚀 Roadmap Estratégico

### v2.6 (Corto Plazo: Consolidación)
*Enfoque en calidad de código, testing y usabilidad de datos.*

- [ ] **Suite de Tests**: Implementar tests unitarios y de integración faltantes.
- [ ] **Exportación**: Soporte para salida CSV y HTML básico.
- [ ] **Multilenguaje**: Facilitar la adición de más idiomas (refactorizar strings).
- [ ] **Comparación**: Implementar funcionalidad básica de `diff` entre reportes JSON.

🗓️ **Estimado**: Q1 2025

### v3.0 (Medio Plazo: Expansión)
*Enfoque en integración y visualización.*

- [ ] **Dashboard Web**: Servidor ligero (Flask/FastAPI) para visualizar reportes históricos.
- [ ] **Base de Datos**: Integración opcional con SQLite para historial de scans.
- [ ] **Docker**: Containerización oficial de la herramienta.
- [ ] **API REST**: Exponer el motor de escaneo vía API para integraciones de terceros.

🗓️ **Estimado**: Q2-Q3 2025

### v4.0 (Largo Plazo: Inteligencia)
*Enfoque en análisis avanzado y gran escala.*

- [ ] **Machine Learning**: Detección de anomalías en patrones de tráfico.
- [ ] **Modo Distribuido**: Orquestación de múltiples nodos de scanning.
- [ ] **Integración SIEM**: Conectores nativos para Splunk, ELK, Wazuh.

🗓️ **Estimado**: 2026+

---

## 🗑️ Ideas Descartadas

Propuestas que evalué pero no implementaré:

| Propuesta | Razón del Descarte |
| :--- | :--- |
| ❌ **Soporte Windows nativo** | Complejidad de mantener dos codebases yo solo. Mejor usar WSL2/Docker. |
| ❌ **GUI gráfica (GTK/Qt)** | RedAudit es una herramienta de automatización CLI/API. Fuera del scope. |

---

## 🤝 ¿Quieres Participar?

Si deseas contribuir a alguna de estas features:

1.  🔍 Revisa si ya existe un [Issue relacionado](https://github.com/dorinbadea/RedAudit/issues).
2.  💬 Comenta tu interés antes de empezar (para evitar trabajo duplicado).
3.  📖 Lee [CONTRIBUTING.md](https://github.com/dorinbadea/RedAudit/blob/main/CONTRIBUTING.md).
4.  🐛 Abre un [Discussion](https://github.com/dorinbadea/RedAudit/discussions) para nuevas ideas.

**Especialmente busco ayuda en:**
*   Tests unitarios (ideal para empezar).
*   Traducción a otros idiomas.
*   Documentación y ejemplos de uso.

---

<div align="center">

**Mantenimiento Activo**  
*Última actualización: Diciembre 2025*

<sub>Si este documento no se actualiza en >6 meses, el proyecto puede estar pausado. En ese caso, considera hacer un fork o contactarme.</sub>

</div>

