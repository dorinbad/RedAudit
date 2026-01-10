#!/bin/bash
# RedAudit Lab Setup Script
#
# Usage:
#   ./setup_lab.sh [install|start|stop|remove|status]
#
# This script sets up the "lab_seguridad" Docker environment used for testing RedAudit.
# Network: 172.20.0.0/24
#
# Updated: 2026-01-10 - Phase 4 verified commands

LAB_NET="lab_seguridad"
LAB_SUBNET="172.20.0.0/24"
LAB_GATEWAY="172.20.0.1"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}[ERROR] Docker is not installed.${NC}"
        echo "Please install Docker first: curl -fsSL https://get.docker.com | sh"
        exit 1
    fi
}

create_network() {
    if ! docker network ls | grep -q "$LAB_NET"; then
        echo -e "${GREEN}[+] Creating network $LAB_NET ($LAB_SUBNET)...${NC}"
        docker network create --subnet "$LAB_SUBNET" --gateway "$LAB_GATEWAY" "$LAB_NET"
    else
        echo -e "${GREEN}[+] Network $LAB_NET already exists.${NC}"
    fi
}

install_targets() {
    check_docker
    create_network

    echo -e "${GREEN}[+] Provisioning Lab Targets...${NC}"

    # === CORE GROUP (Web & Legacy) ===

    # .10 Juice Shop (Web/Node.js)
    echo -e "${YELLOW}[*] Installing juiceshop (.10)...${NC}"
    docker run -d --name juiceshop --net "$LAB_NET" --ip 172.20.0.10 \
        bkimminich/juice-shop >/dev/null 2>&1 || echo "juiceshop exists"

    # .11 Metasploitable (Legacy Linux)
    echo -e "${YELLOW}[*] Installing metasploitable (.11)...${NC}"
    docker run -d --name metasploitable --net "$LAB_NET" --ip 172.20.0.11 -t \
        tleemcjr/metasploitable2 >/dev/null 2>&1 || echo "metasploitable exists"

    # .12 DVWA (PHP/SQLi)
    echo -e "${YELLOW}[*] Installing dvwa (.12)...${NC}"
    docker run -d --name dvwa --net "$LAB_NET" --ip 172.20.0.12 \
        vulnerables/web-dvwa >/dev/null 2>&1 || echo "dvwa exists"

    # .13 WebGoat (Java/OWASP)
    echo -e "${YELLOW}[*] Installing webgoat (.13)...${NC}"
    docker run -d --name webgoat --net "$LAB_NET" --ip 172.20.0.13 \
        webgoat/webgoat >/dev/null 2>&1 || echo "webgoat exists"

    # .14 Hackazon (E-commerce)
    echo -e "${YELLOW}[*] Installing hackazon (.14)...${NC}"
    docker run -d --name hackazon --net "$LAB_NET" --ip 172.20.0.14 \
        ianwijaya/hackazon >/dev/null 2>&1 || echo "hackazon exists"

    # .15 bWAPP (Buggy App)
    echo -e "${YELLOW}[*] Installing bwapp (.15)...${NC}"
    docker run -d --name bwapp --net "$LAB_NET" --ip 172.20.0.15 \
        raesene/bwapp >/dev/null 2>&1 || echo "bwapp exists"

    # === PHASE 4 GROUP (SSH, SMB, SNMP, AD, SCADA, IoT) ===

    # .20 SSH Target (Ubuntu with synced password)
    echo -e "${YELLOW}[*] Installing target-ssh-lynis (.20)...${NC}"
    docker run -d --name target-ssh-lynis --net "$LAB_NET" --ip 172.20.0.20 \
        -e SSH_ENABLE=true -e USER_PASSWORD=redaudit -e USER_NAME=auditor \
        rastasheep/ubuntu-sshd >/dev/null 2>&1 || echo "target-ssh-lynis exists"

    # .30 SMB Simulator (replaces heavy Windows 11)
    echo -e "${YELLOW}[*] Installing target-windows (.30) - SMB Simulator...${NC}"
    docker run -d --name target-windows --net "$LAB_NET" --ip 172.20.0.30 \
        -e USER="docker" -e PASS="password123" \
        dperson/samba -u "docker;password123" -s "Public;/tmp;yes;no;yes;all;none" \
        >/dev/null 2>&1 || echo "target-windows exists"

    # .40 SNMP v3 Target
    echo -e "${YELLOW}[*] Installing target-snmp (.40)...${NC}"
    docker run -d --name target-snmp --net "$LAB_NET" --ip 172.20.0.40 \
        polinux/snmpd >/dev/null 2>&1 || echo "target-snmp exists"

    # .50 OpenPLC (SCADA/Modbus)
    echo -e "${YELLOW}[*] Installing openplc-scada (.50)...${NC}"
    docker run -d --name openplc-scada --net "$LAB_NET" --ip 172.20.0.50 \
        -p 8443:8443 ghcr.io/autonomy-logic/openplc-runtime:latest \
        >/dev/null 2>&1 || echo "openplc-scada exists"

    # .51 Conpot (ICS Honeypot)
    echo -e "${YELLOW}[*] Installing conpot-ics (.51)...${NC}"
    docker run -d --name conpot-ics --net "$LAB_NET" --ip 172.20.0.51 \
        honeynet/conpot:latest >/dev/null 2>&1 || echo "conpot-ics exists"

    # .60 Samba AD (Active Directory with unique realm/domain)
    echo -e "${YELLOW}[*] Installing samba-ad (.60) - Takes 3-5 min to provision...${NC}"
    docker run -d --name samba-ad --net "$LAB_NET" --ip 172.20.0.60 \
        --hostname dc1 --privileged \
        -e REALM=AD.LAB.LOCAL -e DOMAIN=REDAUDITAD \
        -e ADMIN_PASSWORD=P@ssw0rd123 -e DNS_FORWARDER=8.8.8.8 \
        nowsci/samba-domain >/dev/null 2>&1 || echo "samba-ad exists"

    # .70 IoT Camera (GoAhead RCE)
    echo -e "${YELLOW}[*] Installing iot-camera (.70)...${NC}"
    docker run -d --name iot-camera --net "$LAB_NET" --ip 172.20.0.70 \
        vulhub/goahead:3.6.4 >/dev/null 2>&1 || echo "iot-camera exists"

    # .71 IoT Router (Web vuln placeholder)
    echo -e "${YELLOW}[*] Installing iot-router (.71)...${NC}"
    docker run -d --name iot-router --net "$LAB_NET" --ip 172.20.0.71 \
        webgoat/webgoat >/dev/null 2>&1 || echo "iot-router exists"

    echo -e "${GREEN}[OK] All targets installed. Run './setup_lab.sh status' to check.${NC}"
    echo -e "${YELLOW}[!] Note: samba-ad (.60) takes 3-5 minutes for first provisioning.${NC}"
}

start_lab() {
    check_docker
    echo -e "${GREEN}[+] Starting all containers in $LAB_NET...${NC}"
    docker start $(docker ps -aq --filter "network=$LAB_NET") 2>/dev/null
    echo -e "${GREEN}[OK] Lab started.${NC}"
}

stop_lab() {
    check_docker
    echo -e "${GREEN}[+] Stopping all containers in $LAB_NET...${NC}"
    docker stop $(docker ps -aq --filter "network=$LAB_NET") 2>/dev/null
    echo -e "${GREEN}[OK] Lab stopped.${NC}"
}

remove_lab() {
    check_docker
    echo -e "${RED}[!] WARNING: This will remove all lab containers.${NC}"
    read -p "Are you sure? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rm -f $(docker ps -aq --filter "network=$LAB_NET") 2>/dev/null
        docker network rm "$LAB_NET" 2>/dev/null
        echo -e "${GREEN}[OK] Lab removed.${NC}"
    fi
}

status_lab() {
    check_docker
    echo -e "${GREEN}=== RedAudit Lab Status ===${NC}"
    echo -e "Network: $LAB_NET ($LAB_SUBNET)"
    echo
    docker ps -a --filter "network=$LAB_NET" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo
    echo -e "Ping Check:"
    for ip in 10 11 12 13 14 15 20 30 40 50 51 60 70 71; do
        target="172.20.0.$ip"
        if ping -c1 -W1 "$target" &>/dev/null; then
             echo -e "  $target: ${GREEN}UP${NC}"
        else
             echo -e "  $target: ${RED}DOWN${NC}"
        fi
    done
}

case "$1" in
    install)
        install_targets
        ;;
    start)
        start_lab
        ;;
    stop)
        stop_lab
        ;;
    remove)
        remove_lab
        ;;
    status)
        status_lab
        ;;
    *)
        echo "Usage: $0 {install|start|stop|remove|status}"
        exit 1
        ;;
esac
