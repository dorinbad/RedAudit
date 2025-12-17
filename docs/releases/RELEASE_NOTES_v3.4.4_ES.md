# Notas de la versión v3.4.4 - Hotfix UX de Defaults

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.4.4.md)

**Fecha de publicación**: 2025-12-17

## Resumen

RedAudit v3.4.4 es un hotfix pequeño que mejora el flujo de defaults del wizard interactivo y añade una nota práctica tras actualizar.

## Correcciones

- **Flujo de defaults**: Al elegir "Usar defaults y continuar" ahora sí se aplican correctamente. Iniciar "inmediatamente" ya no re-pregunta parámetros, y puede reutilizar objetivos guardados cuando estén disponibles.
- **Nota de actualización**: Si el banner no refresca la versión tras actualizar, reinicia el terminal o ejecuta `hash -r` (zsh/bash).

## Instrucciones de actualización

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

*RedAudit v3.4.4 - Defaults más suaves en el wizard.*
