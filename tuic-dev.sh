#!/bin/bash

# SCP Foundation - Tuic v5 Deployment Protocol Simplified

# Define color codes
red='\e[31m'
green='\e[92m'
yellow='\e[33m'
plain='\e[0m'
underline='\e[4m'
blink='\e[5m'
cyan='\e[96m'
reset='\e[0m'

# Function to display messages
msg() {
    case $1 in
        err) echo -e "${red}[ERROR]${plain} $2" ;;
        warn) echo -e "${yellow}[WARNING]${plain} $2" ;;
        ok) echo -e "${green}[OK]${plain} $2" ;;
        info) echo -e "[INFO] $2" ;;
        *) echo -e "$2" ;;
    esac
}

# Check for root privileges
[[ $EUID -ne 0 ]] && msg err "Root clearance required." && exit 1

# Detect package manager
# Detect package manager and ensure script compatibility
cmd=$(type -P apt-get || type -P yum)
[[ ! $cmd ]] && echo "This script is only working with ${yellow}(Ubuntu or Debian or CentOS)${none}, ya dig?" && exit 1


# We gotta have systemd
[[ ! $(type -P systemctl) ]] && {
    echo "Your system's missing ${yellow}(systemctl)${none}, try running: ${yellow} ${cmd} update -y;${cmd} install systemd -y ${none} for fixing.." && exit 1
}

# Initialization
workspace="/opt/tuic"
service="/etc/systemd/system/tuic.service"
dependencies="wget unzip jq net-tools socat curl cron"
cert_dir="/root/cert"
fullchain="$cert_dir/fullchain.pem"
private_key="$cert_dir/private.key"

# Ensure the certificate directory exists
mkdir -p "$cert_dir"

# Simplify the installation of missing packages
install_pkg() {
    msg info "Checking and installing missing dependencies..."
    $cmd update -y
    for package in $dependencies; do
                if ! command -v $package &>/dev/null; then
                    msg warn "Installing $package..."
                    $cmd install -y $package
                fi
            done
        }

        # Function to get the public IP of the server
        get_ip() {
            ipv4=$(curl -s4 https://api.ipify.org)
            ipv6=$(curl -s6 https://api6.ipify.org)
        }

        # Verify domain is pointing to the server's IP
        check_domain() {
            local domain=$1
            get_ip
            # 使用 dig 查询域名的 A 和 AAAA 记录
            local domain_ips_v4=$(dig +short A $domain @1.1.1.1)
            local domain_ips_v6=$(dig +short AAAA $domain @1.1.1.1)
            # 检查是否有 IPv4 或 IPv6 地址匹配
            { [[ $domain_ips_v4 =~ $ipv4 ]] || [[ $domain_ips_v6 =~ $ipv6 ]] ;} &&
                check_domain() {
                    local domain=$1
                    if ! ping -c 1 $domain &> /dev/null; then
                        msg err "Domain $domain does not resolve to this server IP."
                        exit 1
                    fi
                }

                msg() {
                    local color=$1
                    local message=$2
                    case $color in
                        ok) echo -e "\e[32m$message\e[0m" ;;
                        err) echo -e "\e[31m$message\e[0m" ;;
                        info) echo -e "\e[34m$message\e[0m" ;;
                        warn) echo -e "\e[33m$message\e[0m" ;;
                        *) echo $message ;;
                    esac
                }

                                check_domain $domain

                                msg ok "Domain $domain correctly resolves to this server IP." || {
                                msg err "Domain $domain does not resolve to this server IP."
                                exit 1
                            }
                        } # Add this closing curly brace
                msg info "Tuic is already running."
            else
                systemctl start tuic
                if [ $? -eq 0 ]; then
                    msg ok "Tuic started."
                    while IFS= read -r line
                    do
                        IFS=', ' read -ra pairs <<< "$line"
                        for pair in "${pairs[@]}"; do
                            key=$(echo $pair | cut -d'=' -f1)
                            value=$(echo $pair | cut -d'=' -f2)
                            if [[ "$key" == "address" ]] || [[ "$key" == "port" ]]; then
                                echo -n "${value}, "
                            elif [[ "$key" != "tuic" ]]; then
                                echo -n "${key}=${value}, "
                            fi
                        done
                    done < "${workspace}/client.txt" | sed 's/, $//'
                    echo ""
                    echo "----------------------------------------------------------------------------"
                    echo ""
            return 0
        else
            msg err "Tuic failed to start."
            systemctl status tuic
            return 1
        fi
    fi
}

 stop() {
     if [[ ! -e "$service" ]]; then
         echo "Tuic ain't installed yet, bro."
     else
         systemctl stop tuic && echo "Tuic has been stopped, bro."
     fi
 }
# Main menu function remains unchanged
restart() {
    stop
    sleep 2  # Optional: Wait for 2 seconds
    run
}

manage() {
    echo "1. Start Tuic"
    echo "2. Stop Tuic"
    echo "3. Restart Tuic"
    echo "4. Back to main menu"
    read -p "Select operation (1/2/3/4): " operation

    case $operation in
        1) run ;;
        2) stop ;;
        3) restart ;;
        4) menu ;;
        *) msg err "Invalid operation." ;;
    esac
}

menu() {
    echo -e "${cyan}${underline}${blink}Tuic, faster than ever, even in adversity.${reset}"
    msg ok "1. Install Tuic"
    msg warn "2. Uninstall Tuic"
    msg info "3. Manage Tuic"
    echo "4. Exit"
    read -p "Select operation (1/2/3/4): " operation

    case $operation in
        1) install ;;
        2) uninstall ;;
        3) manage ;;
        4) exit 0 ;;
        *) msg err "Invalid operation." ;;
    esac
}
 # Usage
 menu