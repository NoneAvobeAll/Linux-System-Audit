#!/usr/bin/env bash
#===============================================================================
# Linux System Slowness Audit Tool - Professional Edition v1.0.0
# Inspired by: Windows System Slowness Audit Tool by Abubakkar Khan
#
# Author: Abubakkar Khan (Linux edition concept)
# Description:
#   Enterprise-grade diagnostic tool for Linux servers.
#   Focus on performance bottlenecks, system health, security posture,
#   and service/application status.
#
# Notes:
#   - Run as root for full visibility: sudo ./linux_system_audit.sh
#   - Target: systemd-based distros (Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, etc.)
#   - Optional tools (auto-detected): vmstat, iostat, mpstat, smartctl, dig, ss, lsof
#===============================================================================

#---------------------------- Global Settings ----------------------------------
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
MAGENTA="\e[35m"
RESET="\e[0m"

LOG_PREFIX="[AUDIT]"

#---------------------------- Helper Functions ---------------------------------

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${LOG_PREFIX} This script should be run as root (use sudo).${RESET}"
        exit 1
    fi
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

hr() {
    printf '%*s\n' "${COLUMNS:-80}" '' | tr ' ' '━'
}

print_header() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║                                                                       ║${RESET}"
    echo -e "${CYAN}║           LINUX SYSTEM AUDIT TOOL v1.0.0 - PROFESSIONAL               ║${RESET}"
    echo -e "${CYAN}║                                                                       ║${RESET}"
    echo -e "${CYAN}║            Developed By: Abubakkar Khan (Linux Edition)               ║${RESET}"
    echo -e "${CYAN}║             System Engineer | Cybersecurity Researcher                ║${RESET}"
    echo -e "${CYAN}║                                                                       ║${RESET}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${RESET}"
    echo
}

print_menu() {
    echo -e "${MAGENTA}═══════════════════════ COMPREHENSIVE AUDIT MENU ═══════════════════════${RESET}"
    echo
    echo -e "${YELLOW}▶ CORE DIAGNOSTICS${RESET}"
    echo -e "  [1]  CPU Usage Analysis              [6]  Systemd Services Status"
    echo -e "  [2]  Memory (RAM) Analysis           [7]  System Logs (24h)"
    echo -e "  [3]  Disk Performance & Space        [8]  Startup/Boot Analysis"
    echo -e "  [4]  Network Performance             [9]  Package Update Status"
    echo -e "  [5]  Top Resource Processes          [10] Hardware & Filesystems"
    echo
    echo -e "${YELLOW}▶ ADVANCED DIAGNOSTICS${RESET}"
    echo -e "  [13] Swap/Pagefile (Virtual Memory) [18] Cron & Systemd Timers"
    echo -e "  [14] Uptime & Boot History          [19] Power & Battery (laptops)"
    echo -e "  [15] Network Latency Test           [20] DNS Performance"
    echo -e "  [16] Security/AV Presence           [21] Disk I/O Wait & Saturation"
    echo -e "  [17] File Descriptor / Handle Usage [22] Critical System Events"
    echo
    echo -e "${YELLOW}▶ STORAGE & BACKUP${RESET}"
    echo -e "  [23] Filesystem Usage & Inodes      [24] LVM / Snapshot Overview"
    echo
    echo -e "${YELLOW}▶ NETWORK & SECURITY${RESET}"
    echo -e "  [25] Open Ports & Listening Services"
    echo -e "  [26] Firewall Status (iptables/nftables/ufw/firewalld)"
    echo -e "  [27] TLS Certificate Expiry (Nginx/Apache, local certs)"
    echo -e "  [28] SMB/NFS Share Check (if present)"
    echo
    echo -e "${YELLOW}▶ APPLICATIONS${RESET}"
    echo -e "  [32] PostgreSQL/MySQL Health (basic service check)"
    echo -e "  [33] Web Server (Nginx/Apache) Health"
    echo -e "  [34] Docker / Container Runtime Status"
    echo -e "  [35] KVM/Libvirt/Hypervisor Presence"
    echo
    echo -e "${YELLOW}▶ SECURITY & COMPLIANCE${RESET}"
    echo -e "  [37] Basic Security Baseline (SSH, sudo, world-writable)"
    echo -e "  [38] Patch Compliance Snapshot (last updates)"
    echo -e "  [39] Suspicious Processes & Binaries"
    echo
    echo -e "${YELLOW}▶ SYSTEM MAINTENANCE${RESET}"
    echo -e "  [40] Logs & Disk Pressure Summary"
    echo -e "  [41] System File Integrity Hints"
    echo -e "  [42] Kernel & Distro Info"
    echo
    echo -e "${YELLOW}▶ UTILITIES${RESET}"
    echo -e "  [11] ★ FULL SYSTEM AUDIT (All Core + Advanced Checks)"
    echo -e "  [12] 📊 Export Report to /var/tmp/linux_system_audit_<timestamp>.log"
    echo -e "  [0]  Exit"
    echo
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${RESET}"
}

pause() {
    echo
    read -r -p "Press Enter to continue..." _
}

#---------------------------- Core Checks -------------------------------------

cpu_usage() {
    echo -e "${YELLOW}[+] CPU USAGE ANALYSIS${RESET}"
    hr
    echo

    if have_cmd lscpu; then
        echo -e "${CYAN}CPU Info:${RESET}"
        lscpu | egrep 'Model name:|CPU\(s\):|Core\(s\) per socket:|Thread' || true
        echo
    fi

    echo -e "${CYAN}Load & Utilization:${RESET}"
    echo -e "Uptime / Load averages:"
    uptime

    if have_cmd mpstat; then
        echo
        echo "mpstat (average over 5 seconds):"
        mpstat 1 5
        echo "from proc/loadavg file:"
        LOAD1=$(cut -d ' ' -f1 /proc/loadavg)
LOAD_COLOR="${YELLOW}"
[ "$(echo "$LOAD1 > 2.0" | bc -l)" -eq 1 ] && LOAD_COLOR="${RED}"
printf "%b\n" "${BLUE}│ ${WHITE}Load Avg   : ${LOAD_COLOR}$(cut -d ' ' -f1-3 /proc/loadavg)${RESET}"

    else
        echo
        echo "mpstat not found; install 'sysstat' package for detailed CPU stats."
    fi
}

memory_usage() {
    echo -e "${YELLOW}[+] MEMORY (RAM) ANALYSIS${RESET}"
    hr
    echo

    echo -e "${CYAN}Memory Usage:${RESET}"
    free -h

    echo
    echo -e "${CYAN}Top 10 Memory-Consuming Processes:${RESET}"
    ps aux --sort=-%mem | head -n 11
}

disk_performance() {
    echo -e "${YELLOW}[+] DISK PERFORMANCE AND SPACE ANALYSIS${RESET}"
    hr
    echo

    echo -e "${CYAN}Filesystem Space Usage (df -h):${RESET}"
    df -hT | grep -E '^/dev|Filesystem'

    echo
    echo -e "${CYAN}Inode Usage (df -i):${RESET}"
    df -iT | grep -E '^/dev|Filesystem'

    echo
    if have_cmd iostat; then
        echo -e "${CYAN}iostat -xz 1 3 (requires sysstat):${RESET}"
        iostat -xz 1 3
    else
        echo -e "${YELLOW}iostat not found; install 'sysstat' for per-device I/O stats.${RESET}"
    fi
}

network_performance() {
    echo -e "${YELLOW}[+] NETWORK PERFORMANCE ANALYSIS${RESET}"
    hr
    echo

    echo -e "${CYAN}Interfaces (ip -brief addr):${RESET}"
    ip -brief addr || ip addr

    echo
    echo -e "${CYAN}Routing Table (ip route):${RESET}"
    ip route

    echo
    echo -e "${CYAN}Basic Connectivity (ping -c3 8.8.8.8):${RESET}"
    ping -c 3 8.8.8.8 || echo -e "${RED}Ping to 8.8.8.8 failed.${RESET}"
}

top_processes() {
    echo -e "${YELLOW}[+] TOP RESOURCE-CONSUMING PROCESSES${RESET}"
    hr
    echo

    echo -e "${CYAN}Top 10 by CPU:${RESET}"
    ps aux --sort=-%cpu | head -n 11

    echo
    echo -e "${CYAN}Top 10 by Memory:${RESET}"
    ps aux --sort=-%mem | head -n 11
}

services_status() {
    echo -e "${YELLOW}[+] SYSTEMD SERVICES STATUS${RESET}"
    hr
    echo

    if ! have_cmd systemctl; then
        echo -e "${RED}systemctl not found; this script assumes a systemd-based system.${RESET}"
        return
    fi

    echo -e "${CYAN}Failed Services:${RESET}"
    systemctl --failed || echo "No failed services."

    echo
    echo -e "${CYAN}Critical Services (ssh, cron, rsyslog, nginx/httpd, mysql/postgres):${RESET}"
    for svc in ssh sshd cron crond rsyslog syslog nginx httpd apache2 mysql mariadb postgresql; do
        if systemctl list-unit-files | grep -q "^${svc}"; then
            systemctl is-active --quiet "$svc" \
                && echo -e "$svc: ${GREEN}active${RESET}" \
                || echo -e "$svc: ${RED}inactive${RESET}"
        fi
    done
}

logs_last_24h() {
    echo -e "${YELLOW}[+] SYSTEM LOGS (Last 24h)${RESET}"
    hr
    echo

    if have_cmd journalctl; then
        echo -e "${CYAN}System Errors (journalctl -p err -S -24h):${RESET}"
        journalctl -p err -S -24h --no-pager | tail -n 50 || echo "No errors in last 24h."
    else
        echo -e "${YELLOW}journalctl not available (non-systemd or logs not accessible).${RESET}"
    fi
}

startup_analysis() {
    echo -e "${YELLOW}[+] STARTUP / BOOT ANALYSIS${RESET}"
    hr
    echo

    if have_cmd systemd-analyze; then
        echo -e "${CYAN}Overall Boot Time:${RESET}"
        systemd-analyze

        echo
        echo -e "${CYAN}Top 15 Services by Startup Time:${RESET}"
        systemd-analyze blame | head -n 15
    else
        echo -e "${YELLOW}systemd-analyze not available.${RESET}"
    fi

    echo
    echo -e "${CYAN}Last Boots (who -b, last reboot):${RESET}"
    who -b
    echo
    last reboot | head -n 10
}

update_status() {
    echo -e "${YELLOW}[+] PACKAGE UPDATE STATUS${RESET}"
    hr
    echo

    if have_cmd apt-get; then
        echo -e "${CYAN}Debian/Ubuntu (apt) status:${RESET}"
        apt-get -s upgrade | grep -E 'upgraded,|Inst ' || echo "Run: sudo apt update && sudo apt upgrade"
    elif have_cmd dnf; then
        echo -e "${CYAN}RHEL/Fedora (dnf) status:${RESET}"
        dnf check-update || echo "Run: sudo dnf check-update"
    elif have_cmd yum; then
        echo -e "${CYAN}RHEL/CentOS (yum) status:${RESET}"
        yum check-update || echo "Run: sudo yum check-update"
    elif have_cmd zypper; then
        echo -e "${CYAN}SUSE (zypper) status:${RESET}"
        zypper lu || echo "Run: sudo zypper refresh && sudo zypper update"
    else
        echo -e "${YELLOW}Unknown package manager; please check updates manually.${RESET}"
    fi
}

hardware_info() {
    echo -e "${YELLOW}[+] HARDWARE & FILESYSTEM INFORMATION${RESET}"
    hr
    echo

    echo -e "${CYAN}CPU / Memory summary:${RESET}"
    lscpu | egrep 'Model name:|CPU\(s\):' || true
    echo
    free -h

    echo
    echo -e "${CYAN}Block Devices (lsblk):${RESET}"
    lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,TYPE

    echo
    if have_cmd smartctl; then
        echo -e "${CYAN}SMART overall status (smartctl -H on /dev/sdX):${RESET}"
        for d in /dev/sd?; do
            echo "Device: $d"
            smartctl -H "$d" 2>/dev/null | grep -i "SMART overall-health" || echo "  SMART not available."
        done
    else
        echo -e "${YELLOW}smartctl not found; install smartmontools for disk health checks.${RESET}"
    fi
}

#---------------------------- Advanced Checks ----------------------------------

swap_analysis() {
    echo -e "${YELLOW}[+] SWAP / VIRTUAL MEMORY ANALYSIS${RESET}"
    hr
    echo

    echo -e "${CYAN}Swap Summary (free -h):${RESET}"
    free -h

    echo
    echo -e "${CYAN}Active Swap Devices (swapon --show):${RESET}"
    swapon --show || echo "No active swap."
}

uptime_boot_history() {
    echo -e "${YELLOW}[+] UPTIME & BOOT HISTORY${RESET}"
    hr
    echo

    echo -e "${CYAN}Uptime:${RESET}"
    uptime -p
    echo
    echo -e "${CYAN}Last Boot:${RESET}"
    who -b
    echo
    echo -e "${CYAN}Recent Reboots:${RESET}"
    last reboot | head -n 10
}

network_latency_test() {
    echo -e "${YELLOW}[+] NETWORK LATENCY TEST${RESET}"
    hr
    echo

    for host in 8.8.8.8 1.1.1.1; do
        echo -e "${CYAN}Ping to $host:${RESET}"
        ping -c 4 "$host" || echo -e "${RED}Failed to ping $host${RESET}"
        echo
    done
}

security_av_presence() {
    echo -e "${YELLOW}[+] SECURITY / AV PRESENCE${RESET}"
    hr
    echo

    echo -e "${CYAN}Known AV/EDR Services:${RESET}"
    for svc in clamav-daemon crowdstrike falcon-sensor sophos sav-protect defender; do
        systemctl list-unit-files 2>/dev/null | grep -qi "$svc" && \
            systemctl is-active --quiet "$svc" && \
            echo -e "$svc: ${GREEN}active${RESET}" || true
    done

    echo
    echo -e "${CYAN}SSH Configuration Quick Check:${RESET}"
    if [[ -f /etc/ssh/sshd_config ]]; then
        grep -E "^(PasswordAuthentication|PermitRootLogin)" /etc/ssh/sshd_config || echo "Default SSH settings (review /etc/ssh/sshd_config)."
    else
        echo "sshd_config not found."
    fi
}

fd_handle_usage() {
    echo -e "${YELLOW}[+] FILE DESCRIPTOR / HANDLE USAGE${RESET}"
    hr
    echo

    echo -e "${CYAN}System-wide FD Limits:${RESET}"
    ulimit -n 2>/dev/null || echo "ulimit not available in non-interactive shell."

    echo
    echo -e "${CYAN}Top 10 Processes by Open File Descriptors:${RESET}"
    if have_cmd lsof; then
        lsof -n 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -nr | head -n 10 \
            | while read -r count pid; do
                cmd=$(ps -p "$pid" -o comm= 2>/dev/null)
                printf "%-8s %-30s %s\n" "$pid" "$cmd" "$count"
              done
    else
        echo -e "${YELLOW}lsof not installed; install lsof for FD analysis.${RESET}"
    fi
}

cron_systemd_timers() {
    echo -e "${YELLOW}[+] CRON & SYSTEMD TIMERS${RESET}"
    hr
    echo

    echo -e "${CYAN}Systemd Timers:${RESET}"
    systemctl list-timers --all 2>/dev/null | head -n 20 || echo "No systemd timers or systemctl not available."

    echo
    echo -e "${CYAN}Cron Jobs (/etc/crontab, cron.d, user crons):${RESET}"
    [[ -f /etc/crontab ]] && cat /etc/crontab
    echo
    ls -1 /etc/cron.d 2>/dev/null || true
    echo
    for u in root $(awk -F: '$3>=1000{print $1}' /etc/passwd); do
        echo "--- crontab for $u ---"
        crontab -l -u "$u" 2>/dev/null || echo "No crontab for $u"
    done
}

power_battery() {
    echo -e "${YELLOW}[+] POWER & BATTERY STATUS${RESET}"
    hr
    echo

    if [[ -d /sys/class/power_supply ]]; then
        echo -e "${CYAN}Power Supply Info:${RESET}"
        ls /sys/class/power_supply
        echo
        for bat in /sys/class/power_supply/BAT*; do
            [[ -d "$bat" ]] || continue
            echo "Battery: $(basename "$bat")"
            cat "$bat"/{status,capacity,voltage_now,current_now} 2>/dev/null
            echo
        done
    else
        echo "No battery/power_supply directory; likely a server or desktop."
    fi
}

dns_performance() {
    echo -e "${YELLOW}[+] DNS PERFORMANCE TEST${RESET}"
    hr
    echo

    if have_cmd dig; then
        for d in google.com cloudflare.com github.com; do
            echo -e "${CYAN}dig $d (timing):${RESET}"
            dig "$d" +stats +noall +answer | sed -n '1,5p'
            echo
        done
    else
        echo -e "${YELLOW}dig not found; using getent + time as fallback.${RESET}"
        for d in google.com cloudflare.com github.com; do
            echo -e "${CYAN}Resolving $d via getent hosts:${RESET}"
            /usr/bin/time -f "Time: %E" getent hosts "$d" 2>&1 | sed -n '1,3p'
            echo
        done
    fi
}

disk_io_wait_saturation() {
    echo -e "${YELLOW}[+] DISK I/O WAIT & SATURATION${RESET}"
    hr
    echo

    if have_cmd iostat; then
        echo -e "${CYAN}iostat -xz 1 3:${RESET}"
        iostat -xz 1 3
    else
        echo -e "${YELLOW}iostat not found; install 'sysstat' for detailed I/O wait analysis.${RESET}"
    fi

    echo
    echo -e "${CYAN}Load average vs CPU count:${RESET}"
    cpu_count=$(nproc)
    load1=$(awk '{print $1}' /proc/loadavg)
    echo "CPUs: $cpu_count, Load (1m): $load1"
}

critical_events() {
    echo -e "${YELLOW}[+] CRITICAL SYSTEM EVENTS${RESET}"
    hr
    echo

    if have_cmd journalctl; then
        echo -e "${CYAN}Kernel/OOM/FS Errors in last 24h:${RESET}"
        journalctl -p err -S -24h --no-pager | egrep -i 'kernel|oom|filesystem|I/O error' | tail -n 50 || echo "No critical kernel/fs events."
    else
        echo "journalctl not available."
    fi
}

fs_usage_inodes() {
    echo -e "${YELLOW}[+] FILESYSTEM USAGE & INODES${RESET}"
    hr
    echo
    df -hT
    echo
    df -iT
}

lvm_snapshot_overview() {
    echo -e "${YELLOW}[+] LVM / SNAPSHOT OVERVIEW${RESET}"
    hr
    echo

    if have_cmd lvs; then
        echo -e "${CYAN}Logical Volumes:${RESET}"
        lvs -o vg_name,lv_name,lv_size,lv_attr
    else
        echo "lvm2 tools not installed or no LVM in use."
    fi
}

open_ports() {
    echo -e "${YELLOW}[+] OPEN PORTS & LISTENING SERVICES${RESET}"
    hr
    echo

    if have_cmd ss; then
        ss -tulpn
    else
        netstat -tulpn 2>/dev/null || echo "ss/netstat not available."
    fi
}

firewall_status() {
    echo -e "${YELLOW}[+] FIREWALL STATUS${RESET}"
    hr
    echo

    if have_cmd ufw; then
        echo -e "${CYAN}ufw status:${RESET}"
        ufw status verbose
    fi

    if have_cmd firewall-cmd; then
        echo
        echo -e "${CYAN}firewalld (zones & services):${RESET}"
        firewall-cmd --state || true
        firewall-cmd --list-all 2>/dev/null || true
    fi

    if have_cmd iptables; then
        echo
        echo -e "${CYAN}iptables -L -n:${RESET}"
        iptables -L -n
    fi

    if have_cmd nft; then
        echo
        echo -e "${CYAN}nft list ruleset:${RESET}"
        nft list ruleset
    fi
}

tls_cert_expiry() {
    echo -e "${YELLOW}[+] TLS CERTIFICATE EXPIRY (LOCAL FILES)${RESET}"
    hr
    echo

    if ! have_cmd openssl; then
        echo "openssl not found."
        return
    fi

    cert_dirs=(
        "/etc/ssl/certs"
        "/etc/nginx"
        "/etc/apache2"
        "/etc/httpd"
    )

    find "${cert_dirs[@]}" -type f \( -name "*.crt" -o -name "*.pem" \) 2>/dev/null | while read -r cert; do
        end_date=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
        [[ -z "$end_date" ]] && continue
        end_ts=$(date -d "$end_date" +%s 2>/dev/null)
        now_ts=$(date +%s)
        days_left=$(( (end_ts - now_ts) / 86400 ))
        echo -e "${CYAN}$cert${RESET} -> Expires in ${days_left} days ($end_date)"
    done | sort -k6n || echo "No local certificates parsed."
}

smb_nfs_check() {
    echo -e "${YELLOW}[+] SMB / NFS SHARE CHECK${RESET}"
    hr
    echo

    echo -e "${CYAN}Mounted Network Filesystems:${RESET}"
    mount | egrep ' type (nfs|nfs4|cifs|smb3?) ' || echo "No NFS/SMB mounts detected."
}

db_health() {
    echo -e "${YELLOW}[+] DATABASE SERVICES HEALTH (PostgreSQL/MySQL)${RESET}"
    hr
    echo

    for svc in postgresql mysql mariadb; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
            systemctl is-active --quiet "$svc" \
                && echo -e "$svc: ${GREEN}active${RESET}" \
                || echo -e "$svc: ${RED}inactive${RESET}"
        fi
    done
}

web_server_health() {
    echo -e "${YELLOW}[+] WEB SERVER HEALTH (Nginx/Apache)${RESET}"
    hr
    echo

    for svc in nginx apache2 httpd; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
            systemctl is-active --quiet "$svc" \
                && echo -e "$svc: ${GREEN}active${RESET}" \
                || echo -e "$svc: ${RED}inactive${RESET}"
        fi
    done
}

docker_status() {
    echo -e "${YELLOW}[+] DOCKER / CONTAINER RUNTIME STATUS${RESET}"
    hr
    echo

    if systemctl list-unit-files 2>/dev/null | grep -q "^docker"; then
        systemctl status docker --no-pager
        echo
        if have_cmd docker; then
            docker ps --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}'
        fi
    elif have_cmd podman; then
        echo "podman detected; showing containers:"
        podman ps
    else
        echo "No Docker or Podman detected."
    fi
}

hypervisor_presence() {
    echo -e "${YELLOW}[+] HYPERVISOR / VIRTUALIZATION PRESENCE${RESET}"
    hr
    echo

    if have_cmd systemd-detect-virt; then
        systemd-detect-virt --vm --container
    fi

    if have_cmd virsh; then
        echo "Libvirt detected; listing VMs (virsh list --all):"
        virsh list --all
    fi
}

security_baseline() {
    echo -e "${YELLOW}[+] BASIC SECURITY BASELINE${RESET}"
    hr
    echo

    echo -e "${CYAN}World-writable directories (excluding /proc, /sys):${RESET}"
    find / -xdev -type d -perm -0002 2>/dev/null | head -n 50

    echo
    echo -e "${CYAN}Users with UID >=1000:${RESET}"
    awk -F: '$3>=1000{print $1":"$3":"$6}' /etc/passwd
}

patch_compliance() {
    echo -e "${YELLOW}[+] PATCH COMPLIANCE SNAPSHOT${RESET}"
    hr
    echo
    update_status
}

suspicious_processes() {
    echo -e "${YELLOW}[+] SUSPICIOUS PROCESSES & BINARIES${RESET}"
    hr
    echo

    echo -e "${CYAN}Processes running from /tmp, /dev, or unknown paths:${RESET}"
    ps aux | egrep ' /tmp/| /dev/shm/| \./' | grep -v egrep || echo "No obvious suspicious process paths."

    echo
    echo -e "${CYAN}Executable files in /tmp (potential malware, review manually):${RESET}"
    find /tmp -type f -perm -111 2>/dev/null | head -n 50 || echo "No executable files in /tmp."
}

logs_disk_pressure() {
    echo -e "${YELLOW}[+] LOGS & DISK PRESSURE SUMMARY${RESET}"
    hr
    echo

    echo -e "${CYAN}Largest directories under /var (du -sh /var/*):${RESET}"
    du -sh /var/* 2>/dev/null | sort -h | tail -n 10
}

system_file_integrity_hint() {
    echo -e "${YELLOW}[+] SYSTEM FILE INTEGRITY HINTS${RESET}"
    hr
    echo

    echo "For full integrity checks, consider:"
    echo "  - debsums (Debian/Ubuntu)"
    echo "  - rpm -Va (RHEL-based)"
    echo "  - aide or tripwire (host-based IDS)"
}

kernel_distro_info() {
    echo -e "${YELLOW}[+] KERNEL & DISTRO INFORMATION${RESET}"
    hr
    echo

    uname -a
    echo
    if [[ -f /etc/os-release ]]; then
        cat /etc/os-release
    fi
}

#---------------------------- Full Audit & Export ------------------------------

full_audit() {
    print_header
    echo -e "${MAGENTA}Starting FULL SYSTEM AUDIT...${RESET}"
    hr
    echo

    cpu_usage
    echo
    memory_usage
    echo
    disk_performance
    echo
    network_performance
    echo
    top_processes
    echo
    services_status
    echo
    logs_last_24h
    echo
    startup_analysis
    echo
    update_status
    echo
    hardware_info
    echo
    swap_analysis
    echo
    uptime_boot_history
    echo
    network_latency_test
    echo
    security_av_presence
    echo
    fd_handle_usage
    echo
    cron_systemd_timers
    echo
    power_battery
    echo
    dns_performance
    echo
    disk_io_wait_saturation
    echo
    critical_events
    echo
    fs_usage_inodes
    echo
    lvm_snapshot_overview
    echo
    open_ports
    echo
    firewall_status
    echo
    tls_cert_expiry
    echo
    smb_nfs_check
    echo
    db_health
    echo
    web_server_health
    echo
    docker_status
    echo
    hypervisor_presence
    echo
    security_baseline
    echo
    patch_compliance
    echo
    suspicious_processes
    echo
    logs_disk_pressure
    echo
    system_file_integrity_hint
    echo
    kernel_distro_info

    echo
    echo -e "${GREEN}FULL AUDIT COMPLETED.${RESET}"
}

export_report() {
    ts=$(date +"%Y%m%d_%H%M%S")
    outfile="/var/tmp/linux_system_audit_${ts}.log"
    echo -e "${YELLOW}Exporting full audit report to ${outfile}${RESET}"
    mkdir -p /var/tmp
    # Use script to capture all output
    script -q -c "$0 --internal-full-audit" "$outfile"
    echo -e "${GREEN}Report saved to ${outfile}${RESET}"
}

#---------------------------- Main Logic ---------------------------------------

if [[ "$1" == "--internal-full-audit" ]]; then
    # Internal use for export_report
    full_audit
    exit 0
fi

require_root

while true; do
    print_header
    print_menu
    read -rp "Select option (0-42): " choice

    case "$choice" in
        1) cpu_usage ;;
        2) memory_usage ;;
        3) disk_performance ;;
        4) network_performance ;;
        5) top_processes ;;
        6) services_status ;;
        7) logs_last_24h ;;
        8) startup_analysis ;;
        9) update_status ;;
        10) hardware_info ;;
        11) full_audit ;;
        12) export_report ;;
        13) swap_analysis ;;
        14) uptime_boot_history ;;
        15) network_latency_test ;;
        16) security_av_presence ;;
        17) fd_handle_usage ;;
        18) cron_systemd_timers ;;
        19) power_battery ;;
        20) dns_performance ;;
        21) disk_io_wait_saturation ;;
        22) critical_events ;;
        23) fs_usage_inodes ;;
        24) lvm_snapshot_overview ;;
        25) open_ports ;;
        26) firewall_status ;;
        27) tls_cert_expiry ;;
        28) smb_nfs_check ;;
        32) db_health ;;
        33) web_server_health ;;
        34) docker_status ;;
        35) hypervisor_presence ;;
        37) security_baseline ;;
        38) patch_compliance ;;
        39) suspicious_processes ;;
        40) logs_disk_pressure ;;
        41) system_file_integrity_hint ;;
        42) kernel_distro_info ;;
        0)  echo -e "${GREEN}Exiting Linux System Audit Tool.${RESET}"; exit 0 ;;
        *)  echo -e "${RED}Invalid selection.${RESET}" ;;
    esac

    pause
done
