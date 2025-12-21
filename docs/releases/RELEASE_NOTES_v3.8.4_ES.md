# Notas de Versión v3.8.4 — Corrección de Consistencia de Colores

**Fecha de lanzamiento:** 2025-12-21

## Resumen

Esta versión de parche corrige un error visual donde los mensajes de estado `[INFO]` aparecían sin su color azul previsto cuando la barra de progreso Rich estaba activa.

---

## Corregido

### Colores de Estado Durante el Progreso

Cuando Rich Progress estaba activo (durante las fases de escaneo de hosts), los mensajes de estado impresos mediante `print_status()` podían perder su formato de color ANSI. Esto ocurría porque el manejo de salida de Rich interfería con las llamadas directas a `print()` usando códigos ANSI sin procesar.

**Solución:** Cuando `_ui_progress_active` es verdadero, el método `print_status()` ahora usa `console.print()` de Rich con markup apropiado:

| Estado | Estilo Rich |
|--------|-------------|
| INFO | `bright_blue` |
| OK | `green` |
| WARN | `yellow` |
| FAIL | `red` |

Esto asegura una visualización de color consistente independientemente del estado de la barra de progreso.

---

## Detalles Técnicos

- **Archivo modificado:** `redaudit/core/auditor.py`
- **Método:** `InteractiveNetworkAuditor.print_status()`
- **Fallback:** Los códigos ANSI estándar aún se usan cuando el progreso no está activo o Rich no está disponible

---

## Actualización

```bash
cd /ruta/a/RedAudit
git pull origin main
```

No se requieren cambios de configuración.

---

[Volver al README](../../README_ES.md) | [Changelog completo](../../CHANGELOG_ES.md)
