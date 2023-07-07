#!/bin/bash
sleep 1
red='\e[31m'
gray='\e[90m'
green='\e[92m'
plain='\e[0m'
white='\e[37m'
magenta='\e[35m'
cyan='\e[96m'
blue='\e[94m'
none='\e[0m'
underline='\e[4m'
blink='\e[5m'
bold='\e[1m'
yellow='\e[33m'
pink='\e[95m'
orange='\e[38;5;208m'
purple='\e[35m'
light_orange='\e[38;5;214m'
light_gray='\e[37m'
light_red='\e[91m'
light_green='\e[92m'
light_yellow='\e[93m'
light_magenta='\e[95m'

error() {
    echo -e "$red$bold$1$plain"
}

success() {
    echo -e "$green$bold$1$plain"
}

warning() {
    echo -e "$yellow$bold$1$plain"
}

info() {
    echo -e "$plain$bold$1$plain"
}

# Use special characters to create a fancy border
border() {
    echo -e "$cyan$bold$underline====================================$plain"
}

# Use different colors and styles to highlight important information
highlight() {
    echo -e "$magenta$bold$blink$1$plain"
}

# Yo, we need root access for this, no exceptions!
[[ $EUID != 0 ]] && echo "Sorry, this gig needs ${yellow}ROOT access.${none} You feel me?" && exit 1

# We're talking yum or apt-get here, so Ubuntu/Debian/CentOS only
cmd=$(type -P apt-get || type -P yum)
[[ ! $cmd ]] && echo "This script is only vibing with ${yellow}(Ubuntu or Debian or CentOS)${none}, ya dig?" && exit 1

# We gotta have systemd
[[ ! $(type -P systemctl) ]] && {
    echo "Your system's missing ${yellow}(systemctl)${none}, try running: ${yellow} ${cmd} update -y;${cmd} install systemd -y ${none} to fix this mess." && exit 1
}


##
workspace="/opt/tuic"
service="/lib/systemd/system/tuic.service"
netpkg="wget unzip jq net-tools socat curl cron"
fullchain="/root/cert/cert.crt"
private_key="/root/cert/private.key"

# Aight, this is Anya's code that peeps if everything's cool, then asks if you're ready to dip or slide back to the main menu.
# Yo, this is Anya's script that checks if things went smooth, and then asks if you wanna bounce or roll back to the main menu.
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
    missing_packages=()
    for package in $*; do
        if ! type -P "$package" > /dev/null; then
            missing_packages+=("$package")
        fi
    done
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        echo "Hold up, we gotta install some stuff first >${missing_packages[*]}"
        $cmd install -y ${missing_packages[*]} &>/dev/null
        if [[ $? != 0 ]]; then
            [[ $cmd =~ yum ]] && yum install epel-release -y &>/dev/null
            $cmd update -y &>/dev/null
            $cmd install -y ${missing_packages[*]} &>/dev/null
        fi
    fi
}

# Let's check if port 80 is free
check_80() {
    if netstat -tuln | grep -q ":80 "; then
        echo "Whoa! Port 80 is already taken by the following:"
        netstat -tuln | awk '/:80 / {print $7}' | cut -d '/' -f1 | xargs kill -9
    else
        echo "Sweet! Port 80 is all yours."
    fi
}

generate_random_uuid() {
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    echo "$uuid"
}

generate_random_password() {
    local length=$1
    local password=$(tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | fold -w "$length" | head -n 1)
    echo "$password"
}

find_unused_port() {
    local port
    while :; do
        port=$(shuf -i 1024-65535 -n 1)
        if ! netstat -ntlp | grep -q -E ":${port}\\s "; then
            echo $port
            break
        fi
    done
}

cert_update() {
    echo "Hold up, we're renewing your certificate."
    ~/.acme.sh/acme.sh --issue -d $1 --standalone --keylength ec-256 --server letsencrypt
    ~/.acme.sh/acme.sh --install-cert -d $1 --ecc --fullchain-file ${workspace}/fullchain.pem --key-file ${workspace}/private_key.pem --reloadcmd "systemctl restart tuic.service"
    echo "Your certificate is chillin' at ${workspace}"
    # Check if the certificate needs to be updated and do it automatically if needed
    ~/.acme.sh/acme.sh --cron --domain $1
    crontab -l | grep -q "$1" && echo "You've already got an auto-renewal job for $1's certificate" ||
    { crontab -l > conf_temp && echo "0 0 * */2 * ~/.acme.sh/acme.sh --cron --domain $1" >> conf_temp && crontab conf_temp && rm -f conf_temp && echo "Added an auto-renewal job for $1's certificate"; }
}

apply_cert() {
    # Check if acme.sh is installed
    [ ! -f "/root/.acme.sh/acme.sh" ] && curl https://get.acme.sh | sh
    echo "We're getting your certificate."
    # Create a directory to store the certificate
    mkdir -p /etc/ssl/private
    # ~/.acme.sh/acme.sh --issue --force --ecc --standalone -d $1 --keylength ec-256 --server letsencrypt
    if [[ $2 == "force" ]]; then
        ~/.acme.sh/acme.sh --issue --force --ecc --standalone -d $1 --keylength ec-256 --server letsencrypt
    else
        ~/.acme.sh/acme.sh --issue --ecc --standalone -d $1 --keylength ec-256 --server letsencrypt
    fi
    ~/.acme.sh/acme.sh --install-cert -d $1 --ecc --fullchain-file ${workspace}/fullchain.pem --key-file ${workspace}/private_key.pem --reloadcmd "systemctl restart tuic.service"
    [ $? -ne 0 ] && { echo "Dang, couldn't get the certificate." && exit 1; }
}

check_cert() {
    if ~/.acme.sh/acme.sh --list | grep -q $1; then
        read -rp "Wanna revoke the existing certificate? (Leave it blank to ignore): " del_cert
        if [[ ${del_cert} == [yY] ]]; then
            echo "Revoking $1's certificate..."
            ~/.acme.sh/acme.sh --revoke -d $1 --ecc
            ~/.acme.sh/acme.sh --remove -d $1 --ecc  # Delete the certificate file
            rm -f ~/.acme.sh/${1}_ecc/${1}.key  # Delete the key file
            apply_cert $1 "force"
        else 
            echo "We're gonna use the existing certificate for you."
            cert_update $1
        fi
    else
        apply_cert $1
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
    echo "Got your service ${service} all set up."
    systemctl daemon-reload
}

create_conf() {
    read -rp "Drop your domain name here: " domain_input
    [[ -z ${domain_input} ]] && echo "Can't leave the domain name empty, bro." && exit 1

    read -rp "Wanna customize the certificate path? (Leave it blank to ignore): " is_self_cert
    if [[ ${is_self_cert} == [yY] ]]; then
        read -rp "Drop your certificate path here: " cert_full_path
        [[ ! -e ${cert_full_path} ]] && echo "Can't find the certificate file ${cert_full_path}, bro." && exit 1
        read -rp "Drop your key path here: " key_full_path
        [[ ! -e ${key_full_path} ]] && echo "Can't find the key file ${key_full_path}, bro." && exit 1
    else
        check_80
        check_cert $domain_input
    fi

    read -rp "Assign a port (Leave it blank for a random one): " port_input
    [[ -z ${port_input} ]] && port_input=$(find_unused_port) && echo "Assigned a random port for you: $port_input"
    read -rp "Drop your UUID here (Leave it blank for a random one): " uuid_input
    [[ -z ${uuid_input} ]] && uuid_input=$(generate_random_uuid) && echo "Generated a random UUID for you: $uuid_input"

    read -rp "Drop your password here (Leave it blank for a random one): " password_input
    [[ -z ${password_input} ]] && password_input=$(generate_random_password 16) && echo "Generated a random password for you: $password_input"

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

    read -rp "Wanna enable certificate fingerprint? (Enter 'y' to enable, or ignore): " not_fingerprint
    if [[ ${not_fingerprint} == [yY] ]]; then
        fingerprint=$(openssl x509 -noout -fingerprint -sha256 -inform pem -in "${workspace}/fullchain.pem" | cut -d '=' -f 2)
        [[ -n ${fingerprint} ]] && echo "Added the certificate fingerprint for you." && echo -e "tuic=${TAG}, address=${domain_input}, port=${port_input}, fingerprint=${fingerprint}, sni=${domain_input}, uuid=${uuid_input}, alpn=h3, password=${password_input}" > client.txt || { echo "Couldn't generate the certificate fingerprint. Check if the certificate is valid, bro." && exit 1; }
    else 
        echo -e "tuic=${TAG}, address=${domain_input}, port=${port_input}, skip-cert-verify=true, sni=${domain_input}, uuid=${uuid_input}, alpn=h3, password=${password_input}" > client.txt
    fi
}

 uninstall() {
     systemctl stop tuic
     systemctl disable --now tuic.service
     rm -rf ${workspace} ${service}
     echo "Tuic's kicked out, bro."
 }
run() {
    if [[ ! -e "$service" ]]; then
        echo "Tuic ain't installed yet, bro." ; back2menu
    fi
    systemctl enable --now tuic.service
    if systemctl status tuic | grep -q "active"; then
        echo -e "${blue}${bold}-------------- Tuic's up and running, bro! -----------------"
        echo ""
        echo -e "${cyan}${bold}-------------- Here's your config ------------------"
        if [[ -r "${workspace}/client.txt" && -f "${workspace}/client.txt" ]]; then
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
            done < "${workspace}/client.txt"
        else
            echo "Error: client.txt file is missing or not readable."
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
        echo ""        
        echo -e "-------------- All slick and easy, bro! ------------------"   
        echo -n "tuic-v5, "
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
        echo -e "${light_orange}${bold}-------------- wakuwaku ------------------${plain}"            
        echo ""
        return 0
    else
        echo -e "-------------- Tuic ain't vibin', bro. --------------"
        echo ""
        echo -e "-------------- We hit a snag! --------------"
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

update() {
    if [[ ! -e "$service" ]]; then
        echo "Tuic ain't installed yet, bro."
    else
        read -rp "Update uuid? (Enter 'y' to update, or ignore): " not_update_uuid
        [[ ${not_update_uuid} == [yY] ]] && read -rp "Enter new uuid: " uuid_input
        
        read -rp "Update password? (Enter 'y' to update, or ignore): " not_update_password
        [[ ${not_update_password} == [yY] ]] && read -rp "Enter new password: " password_input
        
        read -rp "Update port? (Enter 'y' to update, or ignore): " not_update_port
        [[ ${not_update_port} == [yY] ]] && read -rp "Enter new port: " port_input
        
        echo -e "tuic=${TAG}, address=${domain_input}, port=${port_input}, skip-cert-verify=true, sni=${domain_input}, uuid=${uuid_input}, alpn=h3, password=${password_input}" > client.txt
        echo "Tuic's config has been updated, bro."
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
     echo "Grabbin' Tuic."
     REPO_URL="https://api.github.com/repos/EAimTY/tuic/releases/latest"
     TAG=$(wget -qO- -t1 -T2 "${REPO_URL}" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g')
     URL="https://github.com/EAimTY/tuic/releases/download/${TAG}/${TAG}-${ARCH}-unknown-linux-gnu"
     wget -N --no-check-certificate "${URL}" -O tuic-server
     chmod +x tuic-server
     create_systemd
     create_conf
     stop
     exit 1
 }
 menu() {
   echo ""
   echo -e "${light_magenta} Yo, Anya's auto Tuic in the house! ${plain}"
   echo ""
   PS3="$(echo -e "Pick your vibe ${cyan}[1-6]${none}: ")"
   options=("Install" "Start" "Stop" "Uninstall" "Bounce" "Update")
   select option in "${options[@]}"; do
     case $REPLY in
       1) echo "Installin'!" && install ;;
       2) echo "Startin' up!" && run ;;
       3) echo "Shuttin' down!" && stop ;;
       4) echo "Uninstallin'!" && uninstall ;;
       5) echo "Bouncin'!" && exit 1 ;;
       6) echo "Updating!" && update ;;
       *) echo "Invalid option $REPLY" ;;
     esac
   done
 }
 # Usage
 menu