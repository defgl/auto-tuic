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
purple='\e[35m'
reset='\e[0m'
_red() { echo -e ${red}$@${none}; }
_blue() { echo -e ${blue}$@${none}; }
_cyan() { echo -e ${cyan}$@${none}; }
_green() { echo -e ${green}$@${none}; }
_yellow() { echo -e ${yellow}$@${none}; }
_magenta() { echo -e ${magenta}$@${none}; }
_red_bg() { echo -e "\e[41m$@${none}"; }

is_err=$(_red_bg ERROR!)
is_warn=$(_red_bg WARNING!)

err() {
    echo -e "\n$is_err $@\n" && exit 1
}

warn() {
    echo -e "\n$is_warn $@\n"
}

# Function to display messages
msg() {
    timestamp=$(TZ=Asia/Shanghai date "+%Y.%m.%d-%H:%M:%S")
    case $1 in
        err) echo -e "${red}[error | ${reset}${purple}${timestamp}${reset}${red}] $2${reset}" ;;
        warn) echo -e "${yellow}[warning | ${reset}${purple}${timestamp}${reset}${yellow}] $2${reset}" ;;
        ok) echo -e "${green}[success | ${reset}${purple}${timestamp}${reset}${green}] $2${reset}" ;;
        info) echo -e "[info | ${reset}${purple}${timestamp}${reset}] $2${reset}" ;;
        *) echo -e "[log | ${reset}${purple}${timestamp}${reset}] $2${reset}" ;;
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

# Simplify the installation of missing packages and ensure dig command is available
install_pkg() {
    msg info "Checking and installing missing dependencies..."
    
    # Detect package manager and install dig package along with other dependencies
    if command -v apt-get &>/dev/null; then
        apt-get update -y
        apt-get install -y dnsutils ${dependencies[@]}
    elif command -v yum &>/dev/null; then
        yum makecache fast
        yum install -y bind-utils ${dependencies[@]}
    else
        msg err "Unsupported package manager. Script supports apt-get (Debian/Ubuntu) and yum (CentOS/RHEL)."
        exit 1
    fi
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
        msg ok "Domain $domain correctly resolves to this server IP." || {
        msg err "Domain $domain does not resolve to this server IP."
        exit 1
    }
}

is_port_used() {
    if [[ $(type -P netstat) ]]; then
        [[ ! $is_used_port ]] && is_used_port="$(netstat -tunlp | sed -n 's/.*:\([0-9]\+\).*/\1/p' | sort -nu)"
        echo $is_used_port | sed 's/ /\n/g' | grep ^${1}$
        return
    fi
    if [[ $(type -P ss) ]]; then
        [[ ! $is_used_port ]] && is_used_port="$(ss -tunlp | sed -n 's/.*:\([0-9]\+\).*/\1/p' | sort -nu)"
        echo $is_used_port | sed 's/ /\n/g' | grep ^${1}$
        return
    fi
    is_cant_test_port=1
    msg "$is_warn Unable to check if the port is available."
    msg "Please run: $(_yellow "${cmd} update -y; ${cmd} install net-tools -y") to fix this issue."
}


generate_random_uuid() {
    echo $(cat /proc/sys/kernel/random/uuid)
}

generate_random_password() {
    local length=$1
    echo $(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$length")
}

# Function to check if a port is already in use
find_unused_port() {
    local port
    while :; do
        port=$(shuf -i 1024-65535 -n 1)
        if ! ss -tuln | grep -q ":${port} " ; then
            echo $port
            break
        fi
    done
}

# Certificate handling functions (apply_cert, cert_update, check_cert) remain unchanged

cert_update() {
    local domain=$1
    echo "Renewing certificate for ${domain}..."
    ~/.acme.sh/acme.sh --cron --domain $domain
    crontab -l | grep -q "$domain" && echo "Auto-renewal job for ${domain}'s certificate already exists." ||
    { crontab -l > conf_temp && echo "0 0 * */2 * ~/.acme.sh/acme.sh --cron --domain $domain" >> conf_temp && crontab conf_temp && rm -f conf_temp && echo "Added auto-renewal job for ${domain}'s certificate."; }
}

apply_cert() {
    local domain=$1
    local force=$2
    # Check if acme.sh is installed
    if [ ! -f "/root/.acme.sh/acme.sh" ]; then
        echo "Installing acme.sh..."
        curl https://get.acme.sh | sh
    fi
    echo "Getting certificate for ${domain}..."
    if [[ $force == "force" ]]; then
        ~/.acme.sh/acme.sh --issue --force --ecc --standalone -d $domain --keylength ec-256 --server letsencrypt
    else
        ~/.acme.sh/acme.sh --issue --ecc --standalone -d $domain --keylength ec-256 --server letsencrypt
    fi
    ~/.acme.sh/acme.sh --install-cert -d $domain --ecc --fullchain-file /root/cert/fullchain.pem --key-file /root/cert/private.key --reloadcmd "systemctl restart tuic.service"
    [ $? -ne 0 ] && { echo "Failed to get the certificate."; exit 1; }
}

check_cert() {
    local domain=$1
    if ~/.acme.sh/acme.sh --list | grep -q $domain; then
        read -rp "Do you want to revoke the existing certificate? (Leave it blank to ignore): " del_cert
        if [[ ${del_cert} == [yY] ]]; then
            echo "Revoking ${domain}'s certificate..."
            ~/.acme.sh/acme.sh --revoke -d $domain --ecc
            ~/.acme.sh/acme.sh --remove -d $domain --ecc  # Delete the certificate file
            rm -f ~/.acme.sh/${domain}_ecc/${domain}.key  # Delete the key file
            apply_cert $domain "force"
        else 
            echo "Using the existing certificate for ${domain}."
            cert_update $domain
        fi
    else
        apply_cert $domain
    fi
}

# Systemd service creation and configuration functions (create_systemd, create_conf) remain unchanged

create_systemd() {
    cat > $service << EOF
    [Unit]
    Description=Delicately-TUICed high-performance proxy built on top of the QUIC protocol
    Documentation=https://github.com/EAimTY/tuic
    After=network.target

    [Service]
    User=root
    WorkingDirectory=${workspace}
    ExecStart=${workspace}/tuic-server -c config.json
    Restart=on-failure
    RestartPreventExitStatus=1
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable tuic
    msg ok "Systemd service created."
}

create_conf() {
    read -rp "Drop your domain name here: " domain_input
    [[ -z ${domain_input} ]] && msg err "Can't leave the domain name empty, bro." && exit 1
    check_domain $domain_input
    read -rp "Wanna customize the certificate path? (Leave it blank to ignore): " is_self_cert
    if [[ ${is_self_cert} == [yY] ]]; then
        read -rp "Drop your certificate path here: " cert_full_path
        [[ ! -e ${cert_full_path} ]] && msg err "Can't find the certificate file ${cert_full_path}, bro." && exit 1
        read -rp "Drop your key path here: " key_full_path
        [[ ! -e ${key_full_path} ]] && msg err "Can't find the key file ${key_full_path}, bro." && exit 1
    else
        is_port_used 80
        check_cert $domain_input
    fi

    read -rp "Assign a port (Leave it blank for a random one): " port_input
    [[ -z ${port_input} ]] && port_input=$(find_unused_port) && echo "[INFO] Assigned a random port for you: $port_input"
    read -rp "Drop your UUID here (Leave it blank for a random one): " uuid_input
    [[ -z ${uuid_input} ]] && uuid_input=$(generate_random_uuid) && echo "[INFO] Generated a random UUID for you: $uuid_input"
    read -rp "Drop your password here (Leave it blank for a random one): " password_input
    [[ -z ${password_input} ]] && password_input=$(generate_random_password 16) && echo "[INFO] Generated a random password for you: $password_input"


cat > config.json << EOF
{
    "server": "[::]:${port_input}",
    "users": {
        "${uuid_input}": "${password_input}"
    },
    "certificate": "${fullchain}",
    "private_key": "${private_key}",
    "congestion_control": "bbr",
    "alpn": ["h3", "spdy/3.1"],
    "udp_relay_ipv6": true,
    "zero_rtt_handshake": false,
    "auth_timeout": "3s",
    "max_idle_time": "10s",
    "max_external_packet_size": 1500,
    "gc_interval": "3s",
    "gc_lifetime": "15s",
    "log_level": "WARN"
}
EOF

    msg ok "Configuration established."

    read -rp "Wanna enable certificate fingerprint? (Enter 'y' to enable, or ignore): " not_fingerprint
    if [[ ${not_fingerprint} == [yY] ]]; then
        fingerprint=$(openssl x509 -noout -fingerprint -sha256 -inform pem -in "${workspace}/fullchain.pem" | cut -d '=' -f 2)
        [[ -n ${fingerprint} ]] && msg ok "Added the certificate fingerprint for you." && echo -e "Proxy-TUIC = tuic-v5, ${domain_input}, ${port_input}, password=${password_input}, skip-cert-verify=true, sni=${domain_input}, server-cert-fingerprint-sha256=${fingerprint}, uuid=${uuid_input}, alpn=h3" > proxy_surge.ini || { msg err "Couldn't generate the certificate fingerprint. Check if the certificate is valid, bro." && exit 1; }
    else 
        echo -e "Proxy-TUIC = tuic-v5, ${domain_input}, ${port_input}, password=${password_input}, skip-cert-verify=true, sni=${domain_input}, uuid=${uuid_input}, alpn=h3" > proxy_surge.ini
    fi
}
# Functions to manage (install, uninstall, run, stop) Tuic service remain unchanged

install() {
     ARCH=$(uname -m)
     if [[ -e "$service" ]]; then
         read -rp "Reinstall, y/n? " input
         case "$input" in
             y)  uninstall ;;
             *)  back2menu ;;
         esac
     else
         install_pkg $dependencies
     fi
     mkdir -p "${workspace}"
     cd "${workspace}" || exit 1
     echo "We in: $(pwd)"
     msg info "Deploying Tuic..."
     REPO_URL="https://api.github.com/repos/EAimTY/tuic/releases/latest"
     TAG=$(wget -qO- -t1 -T2 "${REPO_URL}" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g')
     URL="https://github.com/EAimTY/tuic/releases/download/${TAG}/${TAG}-${ARCH}-unknown-linux-gnu"
     wget -N --no-check-certificate "${URL}" -O tuic-server
     chmod +x tuic-server
     create_systemd
     create_conf
     run
     msg ok "Tuic deployed successfully."
}

uninstall() {
    systemctl stop tuic
     systemctl disable --now tuic.service
     rm -rf ${workspace} ${service}
    msg ok "Tuic has been decommissioned."
}

run() {
    if systemctl is-active --quiet tuic; then
        msg info "Tuic is already running."
    else
        systemctl start tuic
        if [ $? -eq 0 ]; then
            msg ok "Tuic booted."
            msg ok "------------------------ FOR SURGE USE ONLY ------------------------"
            cat "${workspace}/proxy_surge.ini"
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
         echo "Tuic service not found."
     else
         systemctl stop tuic && warn "Tuic has been stopped."
     fi
 }
# Main menu function remains unchanged
restart() {
    stop
    sleep 2  # Optional: Wait for 2 seconds
    run
}

checkconfig() {
    if [ -f "${workspace}/proxy_surge.ini" ]; then
        cat "${workspace}/proxy_surge.ini"
    else
        msg err "Configuration file not found."
    fi
}

changeconfig() {
    local key=$1
    local prompt=$2
    read -p "Enter new ${prompt} (leave blank to keep current): " new_value
    if [ -n "$new_value" ]; then
        # Update proxy_surge.ini
        sed -i "s/\(${key}=\)[^,]*/\1${new_value}/" "${workspace}/proxy_surge.ini"
        #msg ok "${prompt} updated in proxy_surge.ini."

        # Update config.json
        if [[ "$key" == "port" ]]; then
            sed -i "s/\(\"server\": \"[::]:\)[^\"]*/\1${new_value}/" "${workspace}/config.json"
        elif [[ "$key" == "uuid" ]] || [[ "$key" == "password" ]]; then
            sed -i "s/\(\"${key}\": \"\)[^\"]*/\1${new_value}/" "${workspace}/config.json"
        fi
        _green "${prompt} updated in server end."

        # Special handling for password, uuid and port
        if [[ "$key" == "password" ]] || [[ "$key" == "uuid" ]] || [[ "$key" == "port" ]]; then
            _green "${prompt} updated: ${new_value}."
        fi
    else
        msg info "No changes made."
    fi
}

modify() {
    _green "1. Change port"
    _red "2. Change UUID"
    _yellow "3. Change password"
    echo "4. Display configuration"
    echo "5. Back to main menu"
    read -p "Select operation (1/2/3/4/5): " operation

    case $operation in
        1) changeconfig "port" "port" ;;
        2) changeconfig "uuid" "UUID" ;;
        3) changeconfig "password" "password" ;;
        4) checkconfig ;;
        5) manage ;;
        *) msg err "Invalid operation." ;;
    esac
}

manage() {
    _green "1. Boot"
    _red "2. Stop"
    _yellow "3. Reboot"
    echo "4. Config"
    echo "5. Back to main menu"
    read -p "Select operation (1-5): " operation

    case $operation in
        1) run ;;
        2) stop ;;
        3) restart ;;
        4) modify ;;
        5) menu ;;
        *) msg err "Invalid operation." ;;
    esac
}

menu() {
    _cyan "${cyan}${underline}${blink}Tuic, faster than ever, even in adversity.${reset}\n"
    _green "1. Install"
    _red "2. Uninstall"
    _yellow "3. Manage"
    echo "4. Exit"
    read -p "Select operation (1-4): " operation

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