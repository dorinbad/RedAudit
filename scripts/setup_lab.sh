#!/bin/bash
# RedAudit Lab Setup Script
#
# Usage:
#   ./setup_lab.sh [install|start|stop|remove|status]
#
# This script sets up the "lab_seguridad" Docker environment used for testing RedAudit.
# Network: 172.20.0.0/24

LAB_NET="lab_seguridad"
LAB_SUBNET="172.20.0.0/24"
LAB_GATEWAY="172.20.0.1"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
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

    # 1. Juice Shop (Web) - 172.20.0.10
    docker run -d --name juiceshop --net "$LAB_NET" --ip 172.20.0.10 bkimminich/juice-shop >/dev/null 2>&1 || echo "juiceshop exists"

    # 2. Metasploitable (Legacy Linux) - 172.20.0.11
    docker run -d --name metasploitable --net "$LAB_NET" --ip 172.20.0.11 tleemcjr/metasploitable2 >/dev/null 2>&1 || echo "metasploitable exists"

    # 3. DVWA (PHP/SQLi) - 172.20.0.12
    docker run -d --name dvwa --net "$LAB_NET" --ip 172.20.0.12 vulnerables/web-dvwa >/dev/null 2>&1 || echo "dvwa exists"

    # 4. WebGoat (Java/OWASP) - 172.20.0.13
    docker run -d --name webgoat --net "$LAB_NET" --ip 172.20.0.13 webgoat/webgoat >/dev/null 2>&1 || echo "webgoat exists"

    # 5. bWAPP (Buggy App) - 172.20.0.15
    docker run -d --name bwapp --net "$LAB_NET" --ip 172.20.0.15 raesene/bwapp >/dev/null 2>&1 || echo "bwapp exists"

    # 6. Target SSH (Ubuntu Hardening) - 172.20.0.20
    # Note: Requires a custom image or generic ubuntu with ssh server.
    # Using generic ubuntu:22.04 with ssh install for simulation if custom img missing.
    docker run -d --name target-ssh-lynis --net "$LAB_NET" --ip 172.20.0.20 rastasheep/ubuntu-sshd >/dev/null 2>&1 || echo "target-ssh-lynis exists"

    # 7. Target Windows Simulation (Samba) - 172.20.0.30
    docker run -d --name target-windows --net "$LAB_NET" --ip 172.20.0.30 -e USERNAME=docker -e PASSWORD= neilpang/samba >/dev/null 2>&1 || echo "target-windows exists"

    # 8. SNMP v3 Target - 172.20.0.40
    # Using a generic snmpd container if specific one unavailable, or skipped if complex setup required.
    # docker run -d --name target-snmp --net "$LAB_NET" --ip 172.20.0.40 ....

    # 9. OpenPLC (SCADA) - 172.20.0.50
    docker run -d --name openplc-scada --net "$LAB_NET" --ip 172.20.0.50 -p 8080:8080 openplcproject/openplc:v3 >/dev/null 2>&1 || echo "openplc-scada exists"

    # 10. Conpot (ICS Honeypot) - 172.20.0.51
    docker run -d --name conpot-ics --net "$LAB_NET" --ip 172.20.0.51 honeynet/conpot:latest >/dev/null 2>&1 || echo "conpot-ics exists"

    # 11. Samba AD (Active Directory) - 172.20.0.60
    docker run -d --name samba-ad --net "$LAB_NET" --ip 172.20.0.60 --hostname dc1 --privileged \
        -e REALM=REDAUDIT.LOCAL -e DOMAIN=REDAUDIT -e ADMIN_PASSWORD=P@ssw0rd123 \
        nowsci/samba-domain >/dev/null 2>&1 || echo "samba-ad exists"

    # 12. IoT Camera (Vuln) - 172.20.0.70
    docker run -d --name iot-camera --net "$LAB_NET" --ip 172.20.0.70 vulnerables/cve-2017-8225 >/dev/null 2>&1 || echo "iot-camera exists"

    # 13. IoT Router (Vuln) - 172.20.0.71
    # Reusing WebGoat as generic web vuln placeholder if router img missing
    docker run -d --name iot-router --net "$LAB_NET" --ip 172.20.0.71 owasp/webgoat-8.0 >/dev/null 2>&1 || echo "iot-router exists"

    echo -e "${GREEN}[OK] All targets installed. Run './setup_lab.sh status' to check.${NC}"
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
    docker ps -a --filter "network=$LAB_NET" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.IPs}}"
    echo
    echo -e "Ping Check:"
    for ip in 10 11 12 13 15 20 30 40 50 51 60 70 71; do
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
