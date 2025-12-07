# Guía de Uso de RedAudit

> **Consejo**: Para una explicación técnica detallada (Hilos, Cifrado, etc.), consulta el [Manual de Usuario Profesional](MANUAL_ES.md).



## Instalación
RedAudit está diseñado para sistemas Kali Linux o Debian.

1. **Instalación y Actualización**:
   ```bash
   sudo bash redaudit_install.sh
   # Para modo no interactivo:
   sudo bash redaudit_install.sh -y
   ```
   Esto instala las dependencias necesarias (`nmap`, `python3-cryptography`, etc.) y crea el alias.

2. **Recargar Shell**:
   ```bash
   source ~/.bashrc  # o ~/.zshrc
   ```

3. **Ejecutar**:
   ```bash
   # Modo interactivo
   redaudit
   
   # Modo no interactivo (v2.5)
   sudo redaudit --target 192.168.1.0/24 --mode normal
   ```

## Flujo de Trabajo

### 1. Configuración

#### Modo Interactivo
La herramienta te pedirá:
- **Red Objetivo**: Interfaces detectadas o CIDR manual.
- **Modo de Escaneo**: Normal (Discovery+Top Ports), Rápido o Completo.
- **Hilos**: Número de trabajadores concurrentes.
- **Rate Limit**: Retardo opcional (segundos) entre hosts para sigilo.
- **Cifrado**: Protección opcional con contraseña para los reportes.
- **Directorio de Salida**: Por defecto `~/RedAuditReports`.

#### Modo No Interactivo (v2.5)
Toda la configuración mediante argumentos de línea de comandos:
```bash
sudo redaudit \
  --target 192.168.1.0/24 \
  --mode full \
  --threads 8 \
  --rate-limit 1 \
  --encrypt \
  --output /ruta/personalizada \
  --max-hosts 100
```

### 2. Fases de Ejecución
- **Discovery**: Ping rápido para encontrar hosts vivos.
- **Port Scan**: Escaneo nmap específico por host.
- **Vulnerability Scan**: Revisa servicios web (http/https) contra `whatweb` / `nikto` (si es modo completo).

### 3. Reportes y Cifrado
Los reportes se guardan con fecha `redaudit_YYYYMMDD_HHMMSS`.
- **Texto Plano**: `.json` y `.txt`.
- **Cifrados**: `.json.enc`, `.txt.enc` y `.salt`.

Para descifrar resultados:
```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```
Esto generará archivos `.decrypted` (o restaurará la extensión original) tras verificar la contraseña.

### 4. Logging
Los logs de depuración se guardan en `~/.redaudit/logs/`. Revisa estos archivos si el escaneo falla o se comporta de forma inesperada.

## Rendimiento y Sigilo
### Limitación de Velocidad (Rate Limiting)
RedAudit permite configurar un retardo (en segundos) entre el escaneo de cada host.
- **0s (Por defecto)**: Velocidad máxima. Ideal para auditorías internas donde el ruido no importa.
- **1-5s**: Sigilo moderado. Reduce la probabilidad de activar firewalls de rate-limit simples.
- **>10s**: Sigilo alto. Ralentiza significativamente la auditoría pero minimiza el riesgo de detección y congestión.

**Nota sobre el Heartbeat**: Si usas un retardo alto (ej. 60s) con muchos hilos, el escaneo puede parecer "congelado". Revisa el log o el estado del heartbeat.

### Deep Scan Adaptativo y Captura de Tráfico
RedAudit intenta automáticamente un "Deep Scan Adaptativo" en hosts que:
1.  **Tienen más de 8 puertos abiertos**
2.  **Tienen servicios sospechosos** (socks, proxy, vpn, tor, nagios, etc.)
3.  **Tienen muy pocos puertos (<=3)**
4.  **Tienen puertos abiertos pero no se detectó información de versión**
 
- **Estrategia Adaptativa**: Ejecuta un escaneo de 2 fases (primero TCP agresivo, luego UDP/SO solo si la Fase 1 no encontró identidad MAC/SO) para identificar hosts complejos.
- **Captura de Tráfico**: Como parte del Deep Scan, si `tcpdump` está disponible, captura un **snippet de 50 paquetes** (máx 15s) del tráfico del host.
    - Guarda archivos `.pcap` en tu directorio de reportes.
    - Si `tshark` está instalado, incluye un resumen de protocolos en el reporte JSON.
    - *Defensa*: La duración de captura está estrictamente limitada para prevenir bloqueos.

---

RedAudit se distribuye bajo **GPLv3**. Consulta [LICENSE](../LICENSE) para más detalles.
