# Notas de la Versión v4.4.3 de RedAudit

[![View in English](https://img.shields.io/badge/View_in-English-blue.svg)](https://github.com/dorinbadea/RedAudit/blob/v4.4.3/docs/releases/RELEASE_NOTES_v4.4.3.md)

Esta versión de hotfix soluciona el ruido crítico en los registros de las sondas mDNS, corrige un error de pérdida de datos en la verificación sin agentes debido a incompatibilidades de tipos, y aumenta la cobertura de pruebas para los componentes principales de escaneo.

## 🐛 Correcciones

* **Supresión de Ruido en Registros mDNS**:
  * Anteriormente, la sonda mDNS en `_run_low_impact_enrichment` volcaba trazas completas de `TimeoutError` en los registros cuando los hosts no respondían.
  * Esto ha sido parcheado para manejar los tiempos de espera con elegancia como comportamiento esperado (registro a nivel de depuración), reduciendo significativamente el desorden en los registros durante los escaneos.

* **Restauración de Datos de Verificación Sin Agentes**:
  * Se corrigió una regresión donde los resultados de las sondas sin agentes (como versiones de SO de `rpcclient` o `snmpwalk`) se descartaban.
  * El problema fue causado por la lógica de `run_agentless_verification` que filtraba objetos de clase de datos `Host` durante la creación del índice. Esto se ha corregido para manejar tanto diccionarios heredados como objetos `Host` modernos de forma transparente.

* **Análisis SNMP Más Seguro**:
  * Se corrigió un error de sintaxis regex en el analizador SNMP `sysDescr` que podía causar fallos al eliminar prefijos de tipo (ej. `STRING:`).

## 🧪 Mejoras Técnicas

* **Aumento de Cobertura de Pruebas**: Se añadieron pruebas unitarias específicas para `auditor_scan.py` cubriendo rutas de fallo para el enriquecimiento DNS, mDNS y SNMP.
* **Pruebas Consolidadas**: Las nuevas pruebas se han integrado en `test_auditor_core.py` para mantener una arquitectura de pruebas más limpia.

---

**Registro de Cambios Completo**: [v4.4.2...v4.4.3](https://github.com/dorinbadea/RedAudit/compare/v4.4.2...v4.4.3)
