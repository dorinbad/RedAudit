# Manual de Usuario de RedAudit v2.6.1

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](MANUAL_EN.md)

**Versión**: 2.6.1  
**Audiencia objetivo**: Analistas de Seguridad, Administradores de Sistemas  
**Licencia**: GPLv3  

## Tabla de Contenidos

1. [Introducción](#1-introducción)
2. [Instalación y Configuración](#2-instalación-y-configuración)
3. [Nuevas Características (v2.6.1)](#3-nuevas-características-v261)
4. [Arquitectura del Sistema](#4-arquitectura-del-sistema)
5. [Matriz de Activación de Herramientas](#5-matriz-de-activación-de-herramientas)
6. [Lógica de Escaneo](#6-lógica-de-escaneo)
7. [Subsistema de Cifrado](#7-subsistema-de-cifrado)
8. [Monitorización (Heartbeat)](#8-monitorización-heartbeat)
9. [Guía de Descifrado](#9-guía-de-descifrado)
10. [Solución de Problemas](#10-solución-de-problemas)
11. [Glosario](#11-glosario)
12. [Aviso Legal](#12-aviso-legal)

---

## 1. Introducción

Este manual proporciona documentación exhaustiva para la operación y configuración de RedAudit. Cubre aspectos técnicos profundos del motor de escaneo, mecanismos de cifrado, integración de herramientas externas y gestión de reportes. RedAudit está diseñado para ser seguro, robusto y fácil de auditar.

## 2. Instalación y Configuración

Asegúrese de que el sistema host cumple los siguientes requisitos:

- **SO**: Kali Linux, Debian, Ubuntu, Parrot OS.
- **Python**: v3.8+.
- **Privilegios**: Root/Sudo (obligatorio para acceso a sockets raw).

### Instalación

Ejecute el script instalador para resolver automáticamente las dependencias (nmap, python-nmap, cryptography) y configurar el alias del sistema.

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

### Configuración del Shell

Después de la instalación, active el alias:

| Distribución | Shell por Defecto | Comando de Activación |
|:---|:---|:---|
| **Kali Linux** (2020.3+) | Zsh | `source ~/.zshrc` |
| **Debian / Ubuntu / Parrot** | Bash | `source ~/.bashrc` |

> **Nota**: Kali usa Zsh por defecto desde 2020. El instalador detecta automáticamente tu shell.

### Configuración de Concurrencia y Rate Limiting

RedAudit prioriza la configuración en tiempo de ejecución vía argumentos CLI.

- **Concurrencia**: `concurrent.futures.ThreadPoolExecutor` paraleliza operaciones.
  - **Alta**: `--threads 20` (redes rápidas).
  - **Baja**: `--threads 2` (conexiones inestables).
- **Rate Limit**: `-r <segundos>` o `--rate-limit <segundos>`. Inyecta `time.sleep()` para evasión de IDS o estabilidad.

## 3. Nuevas Características (v2.6.1)

### Integración de SearchSploit

RedAudit consulta automáticamente ExploitDB cuando detecta versiones de servicios.

- **Activación**: Automática al detectar versiones.
- **Salida**: `ports[].known_exploits` (JSON) y alertas en TXT.

### Integración de TestSSL.sh

Evaluación exhaustiva de vulnerabilidades SSL/TLS.

- **Activación**: Solo en modo `completo` para puertos HTTPS.
- **Detecta**: Heartbleed, POODLE, cifrados débiles, protocolos obsoletos.

## 4. Arquitectura del Sistema

A partir de v2.6, RedAudit utiliza una arquitectura modular organizada como un paquete Python:

| Módulo | Propósito |
|:---|:---|
| `redaudit/core/auditor.py` | Clase orquestadora principal y gestión de hilos. |
| `redaudit/core/scanner.py` | Lógica de escaneo, wrappers de herramientas y sanitización. |
| `redaudit/core/crypto.py` | Implementación criptográfica (PBKDF2, Fernet). |
| `redaudit/core/network.py` | Detección de interfaces de red y validación de IPs. |
| `redaudit/core/reporter.py` | Generación de reportes estructurados (JSON) y legibles (TXT). |
| `redaudit/utils/constants.py` | Constantes de configuración. |
| `redaudit/utils/i18n.py` | Sistema de internacionalización (EN/ES/RO). |

## 5. Matriz de Activación de Herramientas

RedAudit invoca herramientas externas de manera condicional para optimizar el rendimiento y evitar ruido innecesario.

| Herramienta | Condición de Activación | Modo de Escaneo | Ubicación en Salida |
|:------------|:------------------------|:----------------|:--------------------|
| **nmap** | Siempre (motor principal) | Todos | `host.ports[]` |
| **searchsploit** | Cuando servicio tiene versión detectada | Todos | `ports[].known_exploits` |
| **whatweb** | Cuando se detecta puerto HTTP/HTTPS | Todos | `vulnerabilities[].whatweb` |
| **nikto** | Cuando se detecta puerto HTTP/HTTPS | **Solo Completo** | `vulnerabilities[].nikto_findings` |
| **curl** | Cuando se detecta puerto HTTP/HTTPS | Todos | `vulnerabilities[].curl_headers` |
| **wget** | Cuando se detecta puerto HTTP/HTTPS | Todos | `vulnerabilities[].wget_headers` |
| **openssl** | Cuando se detecta puerto HTTPS | Todos | `vulnerabilities[].tls_info` |
| **testssl.sh** | Cuando se detecta puerto HTTPS | **Solo Completo** | `vulnerabilities[].testssl_analysis` |
| **tcpdump** | Durante Deep Scan | Todos (si activado) | `deep_scan.pcap_capture` |
| **tshark** | Después de captura tcpdump | Todos (si activado) | `deep_scan.pcap_capture.tshark_summary` |
| **dig** | Después de escaneo de puertos | Todos | `host.dns.reverse` |
| **whois** | Solo para IPs públicas | Todos | `host.dns.whois_summary` |

### Diagrama de Flujo de Activación

```text
Descubrimiento (nmap -sn)
    │
    ▼
Escaneo de Puertos (nmap -sV)
    │
    ├── ¿Servicio tiene versión? ──▶ searchsploit
    │
    ├── ¿HTTP/HTTPS detectado? ──▶ whatweb, curl, wget
    │   │
    │   └── ¿Modo Completo? ──▶ nikto
    │
    ├── ¿HTTPS detectado? ──▶ openssl
    │   │
    │   └── ¿Modo Completo? ──▶ testssl.sh
    │
    └── ¿Deep Scan necesario?
        ├── tcpdump (captura de tráfico)
        └── tshark (resumen)
    │
    ▼
Enriquecimiento (dig/whois)
```

## 6. Lógica de Escaneo

1. **Descubrimiento**: Barrido ICMP Echo (`-PE`) + ARP (`-PR`) para mapear hosts vivos.
2. **Enumeración**: Escaneos Nmap paralelos basados en el modo seleccionado.
3. **Deep Scan Adaptativo (Automático)**:
    - **Disparadores**: Host con pocos puertos (<=3), demasiados (>8), servicios sospechosos, o sin versiones.
    - **Estrategia (2 Fases)**:
        1. **Fase 1**: TCP Agresivo (`nmap -A -sV ...`).
        2. **Fase 2**: UDP + SO de respaldo (solo si Fase 1 falla identificación).
    - **Resultado**: Datos guardados en `host.deep_scan`.

## 7. Subsistema de Cifrado

Cuando se habilita el cifrado (`--encrypt`), RedAudit asegura los artefactos de salida.

- **Estándar**: **Fernet** (AES-128 CBC + HMAC-SHA256).
- **Derivación de Clave**: PBKDF2HMAC-SHA256 con 480,000 iteraciones.
- **Salt**: 16 bytes aleatorios generados por sesión (`.salt`).
- **Seguridad Operacional**:
  - Permisos de archivo 0o600 (solo dueño).
  - Validación de complejidad de contraseña (longitud 12+, mayúscula, minúscula, número).
  - Limpieza de memoria (best-effort en Python).

## 8. Monitorización (Heartbeat)

Un hilo demonio monitoriza la salud del proceso principal para distinguir entre un escaneo largo legítimo y un bloqueo ("hanging").

- **Funcionamiento**: Revisa la marca de tiempo `self.last_activity` cada 60s.
- **Estados**:
  - **Activo**: Actividad reciente.
  - **Ocupado**: Sin actividad > 60s (normal en escaneos intensos).
  - **Silencioso**: Sin actividad > 300s. Muestra aviso pero NO aborta (los firewalls pueden causar demoras largas).
- **Archivo**: Actualiza un archivo `heartbeat` en logs cada 5 segundos como señal externa.

## 9. Guía de Descifrado

Los reportes cifrados (`.json.enc`, `.txt.enc`) son ilegibles sin la contraseña y el archivo `.salt`.

**Uso:**

```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```

El script buscará automáticamente el archivo `.salt` correspondiente en el mismo directorio.

## 10. Solución de Problemas

Consulte `docs/TROUBLESHOOTING.md` para una lista detallada de códigos de error.

**Problemas Comunes:**

- **"Encryption missing"**: Instale `python3-cryptography`.
- **Pocos puertos encontrados**: El objetivo puede tener firewall filtrando SYN. RedAudit intentará Deep Scan.
- **Acceso Denegado**: Asegúrese de usar `sudo` para las capacidades de socket raw de Nmap.

## 11. Glosario

- **Deep Scan**: Escaneo secundario agresivo activado heurísticamente.
- **Fernet**: Implementación de cifrado simétrico autenticado.
- **PBKDF2**: Función de derivación de claves resistente a fuerza bruta.
- **Heartbeat**: Mecanismo de monitoreo de salud del proceso.
- **Rate Limit**: Retardo forzado entre peticiones de escaneo.

## 12. Aviso Legal

Esta herramienta es **únicamente para auditorías de seguridad autorizadas**. El uso sin consentimiento escrito del propietario de la red es ilegal. RedAudit se distribuye bajo la licencia **GPLv3**.
