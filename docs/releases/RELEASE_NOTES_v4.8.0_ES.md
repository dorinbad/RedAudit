# Notas de Lanzamiento RedAudit v4.8.0

**Fecha de Lanzamiento:** 16 de Enero de 2026
**Tema:** Velocidad y Precisión (Integración RustScan + Nuclei Opt-in)

## 🚀 Arquitectura HyperScan-First (RustScan)

Esta versión introduce **RustScan** como el motor principal para comprobaciones de conectividad TCP de alta velocidad, reemplazando al backend legacy de Masscan.

- **Aceleración Significativa**: El descubrimiento de puertos completo (1-65535) ahora se completa en ~3 segundos en redes locales (vs ~140s con masscan).
- **Fallback Elegante**: Si RustScan no está disponible, RedAudit cambia transparentemente a técnicas estándar de nmap.
- **Informes**: Nuevo objeto `rustscan` en el esquema del informe (se mantiene el alias `masscan` para compatibilidad hacia atrás).

## 📉 Reducción de Ruido (Nuclei Opt-in)

Para agilizar las auditorías de red y respetar los entornos "silenciosos", Nuclei (escaneo de vulnerabilidades con plantillas) está ahora **DESACTIVADO por defecto**.

- **Requiere Opt-in**: Use el nuevo flag `--nuclei` para habilitarlo.
- **Actualización del Asistente**: El modo interactivo ahora sugiere "No" por defecto al preguntar sobre escaneo extensivo de vulnerabilidades web.
- **Por qué**: Nuclei es excelente para seguridad de aplicaciones web pero a menudo excesivo para auditorías de infraestructura de red general, causando tráfico excesivo y timeouts en segmentos densos.

## 🛠️ Mejoras Internas

- **Refactorización de `net_discovery`**: Lógica más limpia separando la fase de descubrimiento de la enumeración.
- **Manejo de Timeouts Mejorado**: Lógica de procesamiento por lotes mejorada para escáneres web para prevenir terminaciones prematuras.
- **Documentación**: Manuales (EN/ES) y Esquemas actualizados para reflejar los cambios en el toolchain.
