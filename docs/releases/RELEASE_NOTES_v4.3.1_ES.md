# RedAudit v4.3.1 - Lanzamiento de Mantenimiento CI

Este es un lanzamiento de mantenimiento que aborda problemas de regresión identificados en el pipeline de CI después del lanzamiento de v4.3.0.

## Corregido

- **Regresiones de Tests CI**: Resueltos desajustes de mocks y alineación de arquitectura para tests de Wizard, Net Discovery y Smart Scan Spec V1.
  - Parcheado `_run_cmd_suppress_stderr` en lugar de `_run_cmd` en los tests de descubrimiento de red para interceptar correctamente las llamadas.
  - Actualizados los tests de aceptación de Deep Scan para verificar el flag `deep_scan_suggested`, alineándose con la arquitectura de escaneo profundo desacoplada introducida en v4.2.
  - Corregidos errores `StopIteration` en tests interactivos del asistente asegurando que los inputs mockeados cubran la secuencia completa de prompts.

Estas correcciones aseguran que las pruebas de Integración Continua del proyecto pasen de manera fiable, validando la estabilidad de las adiciones de características recientes de v4.3.0.
