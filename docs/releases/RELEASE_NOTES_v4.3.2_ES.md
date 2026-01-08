# RedAudit v4.3.2 - Hotfix: Integridad del Lanzamiento

Este lanzamiento resuelve un desajuste de versión crítico que afectó al lanzamiento de v4.3.1.

## Corregido

- **Integridad del Lanzamiento**: Solucionada una inconsistencia donde `pyproject.toml` permanecía en la versión `4.3.0` mientras `VERSION` se actualizaba a `4.3.1`, causando fallos en las comprobaciones de integridad del pipeline CI/CD.
- **Mantenimiento**: Reemplaza al lanzamiento v4.3.1 (que era técnicamente idéntico en comportamiento de código pero falló las pruebas de autovalidación).
