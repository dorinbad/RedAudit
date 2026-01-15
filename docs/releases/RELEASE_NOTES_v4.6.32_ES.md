# v4.6.32: Descubrimiento Paralelo (Velocidad II) 🏎️

**Fecha:** 15-01-2026

Siguiendo la paralelización de HyperScan, la fase completa de **Net Discovery** (DHCP, ARP, Fping, NetBIOS, mDNS, UPnP) ha sido paralelizada.

## 🚀 Rendimiento

- **Protocolos Paralelos**: Todos los protocolos de descubrimiento ahora se ejecutan simultáneamente usando un ThreadPool.
- **Mejora**: Duración de la fase reducida de ~2-3 minutos a ~30-45 segundos (limitada solo por el protocolo más lento, usualmente NetBIOS o UPnP).
- **Cero Pérdida**: Cobertura completa mantenida; los resultados se agregan de forma segura desde todos los hilos.

## 🛠️ Interno

- Refactorizado `discover_networks` para usar `ThreadPoolExecutor`.
