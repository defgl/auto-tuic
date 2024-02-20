#!/bin/bash

# SCP Foundation - Tuic v5 Deployment Protocol Simplified

red='\e[31m'
green='\e[92m'
yellow='\e[33m'
none='\e[0m'

#msg() {
#    case $1 in
#    err) echo -e "${red}[SCP] Error: $2${none}" ;;
#    warn) echo -e "${yellow}[SCP] Warning: $2${none}" ;;
#    ok) echo -e "${green}[SCP] Success: $2${none}" ;;
#    info) echo -e "[SCP] Info: $2" ;;
#    *) echo -e "[SCP] $2" ;;
#    esac
#}

msg() {
    local color_ok="\033[32m"
    local color_info="\033[34m"
    local color_err="\033[31m"
    local color_warn="\033[33m"
    local color_plain="\033[0m"

    local type=$1
    local message=$2

    case $type in
        ok) echo -e "${color_ok}[OK] ${message}${color_plain}" ;;
        info) echo -e "${color_info}[INFO] ${message}${color_plain}" ;;
        err) echo -e "${color_err}[ERROR] ${message}${color_plain}" ;;
        warn) echo -e "${color_warn}[WARNING] ${message}${color_plain}" ;;
        *) echo -e "${color_plain}${message}${color_plain}" ;;
    esac
}

[[ $EUID -ne 0 ]] && msg err "Root clearance required." && exit 1

# We're talking yum or apt-get here, so Ubuntu/Debian/CentOS only
cmd=$(type -P apt-get || type -P yum)
[[ ! $cmd ]] && echo "This script is only vibing with ${yellow}(Ubuntu or Debian or CentOS)${none}, ya dig?" && exit 1

# We gotta have systemd
[[ ! $(type -P systemctl) ]] && {
    echo "Your system's missing ${yellow}(systemctl)${none}, try running: ${yellow} ${cmd} update -y;${cmd} install systemd -y ${none} to fix this mess." && exit 1
}


##
workspace="/opt/tuic"
service="/etc/systemd/system/tuic.service"
dependencies="wget unzip jq net-tools socat curl cron"
fullchain="/root/cert/cert.crt"
private_key="/root/cert/private.key"

back2menu() {
    if [[ $? -eq 0 ]]; then
        echo "Boom! That worked like a charm."
    else
        echo "Uh-oh! Something went sideways."
    fi
    read -rp "Hit 'y' to bounce, or any key to roll back to the main menu: " back2menuInput
    case "$back2menuInput" in
        y) exit 1 ;;
        *) menu ;;
    esac
}

# Yo, we gotta make sure we got all the stuff we need
install_pkg() {
    msg info "Checking dependencies..."
    for package in $dependencies; do
        if ! type -P $package &>/dev/null; then
            msg warn "Installing $package"
            $cmd install -y $package
        fi
    done

  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    echo "Hold up, we gotta install some stuff first >${missing_packages[*]}"
    $cmd install -y ${missing_packages[*]} &>/dev/null

    if [[ $? != 0 ]]; then
      if [[ $cmd =~ yum ]]; then
        yum install epel-release -y &>/dev/null
      fi

      $cmd update -y &>/dev/null
      $cmd install -y ${missing_packages[*]} &>/dev/null
    fi
  fi
}

# Let's check if port 80 is free
#check_80() {
#    if netstat -tuln | grep -q ":80 "; then
#        echo "Whoa! Port 80 is already taken by the following:"
#        netstat -tuln | awk '/:80 / {print $7}' | cut -d '/' -f1 | xargs kill -9
#    else
#        echo "Sweet! Port 80 is all yours."
#    fi
#}

check_host() {
    local domain=$1
    get_ip
    local my_ip=$ip
    is_dns_type="a"
    [[ $(grep ":" <<<$my_ip) ]] && is_dns_type="aaaa"
    local domain_ip=$(_wget -qO- --header="accept: application/dns-json" "https://one.one.one.one/dns-query?name=$domain&type=$is_dns_type" | jq -r '.Answer[0].data')
    if [[ $my_ip != $domain_ip ]]; then
        msg err "Domain resolution discrepancy detected."
        exit 1
    else
        msg ok "Domain resolution verified."
    fi
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
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    msg "$uuid"
}

generate_random_password() {
    local length=$1
    local password=$(tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | fold -w "$length" | head -n 1)
    msg "$password"
}

find_unused_port() {
    local port
    while :; do
        port=$(shuf -i 1024-65535 -n 1)
        if ! netstat -ntlp | grep -q -E ":${port}\\s "; then
            msg $port
            break
        fi
    done
}

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
    ~/.acme.sh/acme.sh --install-cert -d $domain --ecc --fullchain-file ${workspace}/fullchain.pem --key-file ${workspace}/private_key.pem --reloadcmd "systemctl restart tuic.service"
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
    check_host $domain_input
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
    [[ -z ${port_input} ]] && port_input=$(find_unused_port) && msg info "Assigned a random port for you: $port_input"
    read -rp "Drop your UUID here (Leave it blank for a random one): " uuid_input
    [[ -z ${uuid_input} ]] && uuid_input=$(generate_random_uuid) && msg info "Generated a random UUID for you: $uuid_input"

    read -rp "Drop your password here (Leave it blank for a random one): " password_input
    [[ -z ${password_input} ]] && password_input=$(generate_random_password 16) && msg info "Generated a random password for you: $password_input"

    cat > config.json << EOF
{
    "server": "[::]:${port_input}",
    "users": {
        "${uuid_input}": "${password_input}"
    },
    "certificate": "${workspace}/fullchain.pem",
    "private_key": "${workspace}/private_key.pem",
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
        [[ -n ${fingerprint} ]] && msg ok "Added the certificate fingerprint for you." && echo -e "tuic=${TAG}, address=${domain_input}, port=${port_input}, fingerprint=${fingerprint}, sni=${domain_input}, uuid=${uuid_input}, alpn=h3, password=${password_input}" > client.txt || { msg err "Couldn't generate the certificate fingerprint. Check if the certificate is valid, bro." && exit 1; }
    else 
        echo -e "tuic=${TAG}, address=${domain_input}, port=${port_input}, skip-cert-verify=true, sni=${domain_input}, uuid=${uuid_input}, alpn=h3, password=${password_input}" > client.txt
    fi
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
        msg ok "Tuic started."
    fi
        # while IFS= read -r line
        # do
        #     IFS=', ' read -ra pairs <<< "$line"
        #     for pair in "${pairs[@]}"; do
        #         key=$(echo $pair | cut -d'=' -f1)
        #         value=$(echo $pair | cut -d'=' -f2)
        #         if [[ "$key" == "tuic" ]]; then
        #             value=$(echo $value | grep -oP '\d+(\.\d+)*')
        #         fi
        #         echo -e "${grey}$key${none} = ${magenta}$value${none}"
        #     done
        # done < "${workspace}/client.txt"
        #echo ""        
        #echo -e "-------------- All slick and easy, bro! ------------------"   
        #echo -n "tuic-v5"
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
        echo "----------------------------------------------------------------------------"
        msg -e "${light_orange}${bold}-------------- Excusive For Surge ------------------${plain}"            
        echo ""
        return 0
    else
        msg err "Tuic failed to start."
        systemctl status tuic
        return 1
    fi
}

 stop() {
     if [[ ! -e "$service" ]]; then
         echo "Tuic ain't installed yet, bro."
     else
         systemctl stop tuic && echo "Tuic has been stopped, bro."
     fi
     back2menu
 }

install() {
         ARCH=$(uname -m)
     if [[ -e "$service" ]]; then
         read -rp "Reinstall, y/n? " input
         case "$input" in
             y)  uninstall ;;
             *)  back2menu ;;
         esac
     else
         install_pkg $netpkg
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

menu() {
    echo "1. Install Tuic"
    echo "2. Uninstall Tuic"
    echo "3. Run Tuic"
    echo "4. Exit"
    read -p "Select operation (1/2/3/4): " operation

    case $operation in
        1) install ;;
        2) uninstall ;;
        3) run ;;
        4) exit 0 ;;
        *) msg err "Invalid operation." ;;
    esac
}

menu
