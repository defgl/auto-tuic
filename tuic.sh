#!/bin/bash
sleep 1
red='\e[31m'
gray='\e[90m'
green='\e[92m'
plain='\e[0m'
white='\e[37m'
magenta='\e[95m'
cyan='\e[96m'
blue='\e[94m'
none='\e[0m'
underline='\e[4m'
blink='\e[5m'
bold='\e[1m'
yellow='\e[33m'

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

# root
[[ $EUID != 0 ]] && error "抱歉,此操作需要 ${yellow}ROOT用户.${none} 权限" && exit 1

# yum or apt-get, ubuntu/debian/centos
cmd=$(type -P apt-get || type -P yum)
[[ ! $cmd ]] && error "此脚本仅支持 ${yellow}(Ubuntu or Debian or CentOS)${none}." && exit 1

# systemd
[[ ! $(type -P systemctl) ]] && {
    error "此系统缺少 ${yellow}(systemctl)${none}, 请尝试执行:${yellow} ${cmd} update -y;${cmd} install systemd -y ${none}来修复此错误." && exit 1
}

##
workspace="/opt/tuic"
service="/lib/systemd/system/tuic.service"
netpkg="wget unzip jq net-tools socat curl cron"
fullchain="/root/cert/cert.crt"
private_key="/root/cert/private.key"

back2menu() {
    if [[ $? -eq 0 ]]; then
        success "运行成功"
    else
        error "运行失败"
    fi
    read -rp "Enter 'y' to exit, or any key to return to the main menu: " back2menuInput
    case "$back2menuInput" in
        y) exit 1 ;;
        *) menu ;;
    esac
}


# install dependent pkg
install_pkg() {
    missing_packages=()
    for package in $*; do
        if ! type -P "$package" > /dev/null; then
            missing_packages+=("$package")
        fi
    done
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        warning "安装依赖包 >${missing_packages[*]}"
        $cmd install -y ${missing_packages[*]} &>/dev/null
        if [[ $? != 0 ]]; then
            [[ $cmd =~ yum ]] && yum install epel-release -y &>/dev/null
            $cmd update -y &>/dev/null
            $cmd install -y ${missing_packages[*]} &>/dev/null
        fi
    fi
}

check_80() {
    if netstat -tuln | grep -q ":80 "; then
        error "80端口已被以下程序占用"
        netstat -tuln | awk '/:80 / {print $7}' | cut -d '/' -f1 | xargs kill -9
    else
        success "80端口当前可用"
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
    warning "正在为阁下续期证书"
    ~/.acme.sh/acme.sh --issue -d $1 --standalone --keylength ec-256 --server letsencrypt
    ~/.acme.sh/acme.sh --install-cert -d $1 --ecc --fullchain-file ${workspace}/fullchain.pem --key-file ${workspace}/private_key.pem --reloadcmd "systemctl restart tuic.service"
    warning "证书已生成在 ${workspace}"
    # 检查证书是否需要更新，并在需要时自动更新
    ~/.acme.sh/acme.sh --cron --domain $1
    crontab -l | grep -q "$1" && warning "已存在$1的证书自动续期任务" ||
    { crontab -l > conf_temp && echo "0 0 * */2 * ~/.acme.sh/acme.sh --cron --domain $1" >> conf_temp && crontab conf_temp && rm -f conf_temp && warning "已添加$1的证书自动续期任务"; }
}

apply_cert() {
    # 检查 acme.sh 是否已经安装
    [ ! -f "/root/.acme.sh/acme.sh" ] && curl https://get.acme.sh | sh
    warning "正在为阁下申请证书"
    # 创建存储证书的目录
    mkdir -p /etc/ssl/private
    # ~/.acme.sh/acme.sh --issue --force --ecc --standalone -d $1 --keylength ec-256 --server letsencrypt
    ~/.acme.sh/acme.sh --issue --ecc --standalone -d $1 --keylength ec-256 --server letsencrypt
    ~/.acme.sh/acme.sh --install-cert -d $1 --ecc --fullchain-file ${workspace}/fullchain.pem --key-file ${workspace}/private_key.pem --reloadcmd "systemctl restart tuic.service"
    [ $? -ne 0 ] && { error "证书申请失败" && exit 1; }
}

check_cert() {
    if ~/.acme.sh/acme.sh --list | grep -q $1; then
        read -rp "是否撤销已有证书？(留空则忽略)：" del_cert
        if [[ ${del_cert} == [yY] ]]; then
            warning "正在撤销$1的证书..."
            ~/.acme.sh/acme.sh --revoke -d $1 --ecc
            ~/.acme.sh/acme.sh --remove -d $1 --ecc  # 删除证书文件
            rm -f ~/.acme.sh/${1}_ecc/${1}.key  # 删除密钥文件
            rm -f ${workspace}/fullchain.pem ; rm -f ${workspace}/private_key.pem
            apply_cert $1
        else 
            info "将为阁下使用已有证书"
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
    success "已为阁下添加${service}"
    systemctl daemon-reload
}

create_conf() {

    read -rp "请提供域名：" domain_input
    [[ -z ${domain_input} ]] && error "抱歉，域名不能为空" && exit 1

    read -rp "请自定义证书路径(留空则忽略)：" is_self_cert
    if [[ ${is_self_cert} == [yY] ]]; then
        read -rp "请提供证书路径：" cert_full_path
        [[ ! -e ${cert_full_path} ]] && error "抱歉，证书文件${cert_full_path}不存在" && exit 1
        read -rp "请提供秘钥路径：" key_full_path
        [[ ! -e ${key_full_path} ]] && error "抱歉，秘钥文件${key_full_path}不存在" && exit 1
    else
        check_80
        check_cert $domain_input
    fi

    read -rp "请分配端口(留空则随机)：" port_input
    [[ -z ${port_input} ]] && port_input=$(find_unused_port) && warning "已为阁下分配随机端口: $port_input"

    read -rp "请输入UUID(留空则随机)：" uuid_input
    [[ -z ${uuid_input} ]] && uuid_input=$(generate_random_uuid) && warning "已为阁下生成随机UUID: $uuid_input"

    read -rp "请输入密码(留空则随机)：" password_input
    [[ -z ${password_input} ]] && password_input=$(generate_random_password 16) && warning "已为阁下生成随机密码: $password_input"

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
    read -rp "是否启用证书指纹(输入y启用，其他则忽略)：" not_fingerprint
    if [[ ${not_fingerprint} == [yY] ]]; then
        fingerprint=$(openssl x509 -noout -fingerprint -sha256 -inform pem -in "${workspace}/fullchain.pem" | cut -d '=' -f 2)
        [[ -n ${fingerprint} ]] && warning "已添加证书指纹" && echo -e "tuic=${TAG}, address=${domain_input}, port=${port_input}, fingerprint=${fingerprint}, sni=${domain_input}, uuid=${uuid_input}, alpn=h3, password=${password_input}" > client.txt || { error "证书指纹生成失败，请检查证书有效性" && exit 1; }
    else 
        echo -e "tuic=${TAG}, address=${domain_input}, port=${port_input}, skip-cert-verify=true, sni=${domain_input}, uuid=${uuid_input}, alpn=h3, password=${password_input}" > client.txt
    fi
}

uninstall() {
    systemctl stop tuic && \
    systemctl disable --now tuic.service && \
    rm -rf ${workspace} && rm -rf ${service} 
    error "Tuic 已停止并卸载"
}

run() {
    if [[ ! -e "$service" ]]; then
    error "Tuic 未安装" ; back2menu
    fi

    
    systemctl enable --now tuic.service
    if systemctl status tuic | grep -q "active"; then
        # Beautify the output
        success "${blue}${bold}-------------- Tuic 已启动 -----------------"
        echo ""
        # Use 'cat' to display the content of the file, and 'sed' to add indentation and color
        warning "${cyan}${bold}-------------- config ------------------"
        while IFS= read -r line
        do
            # Split the line into key-value pairs
            IFS=', ' read -ra pairs <<< "$line"
            for pair in "${pairs[@]}"; do
                key=$(echo $pair | cut -d'=' -f1)
                value=$(echo $pair | cut -d'=' -f2)
                if [[ "$key" == "tuic" ]]; then
                    # Only keep the numeric part of the value
                    value=$(echo $value | grep -oP '\d+(\.\d+)*')
                fi
                echo -e "${grey}$key${none} = ${magenta}$value${none}"
        done
    done < "${workspace}/client.txt"
        warning "-------------- shortcuts ------------------"       
        echo -n "tuic-v5, "
        while IFS= read -r line
        do
            # Split the line into key-value pairs
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
        success "${cyan}${bold}-------------- wakuwaku ------------------"
        echo ""
        return 0
    else
        error "-------------- Tuic 启动失败 --------------"
        echo ""
        warning "--------------  Err Info  --------------"
        systemctl status tuic
        return 1
    fi
}

stop() {
    if [[ ! -e "$service" ]]; then
        error "Tuic 未安装"
    else
        systemctl stop tuic && info "Tuic 已停止"
    fi
    back2menu
}

install() {
    ARCH=$(uname -m)
    if [[ -e "$service" ]]; then
        read -rp "是否重新安装服务(Y/[N])：" input
        case "$input" in
            y)  uninstall ;;
            *)  back2menu ;;
        esac
    else
        install_pkg $netpkg
    fi
    mkdir -p "${workspace}"
    cd "${workspace}" || exit 1
    info "当前工作目录：$(pwd)"
    info "下载Tuic文件"
    REPO_URL="https://api.github.com/repos/EAimTY/tuic/releases/latest"
    TAG=$(wget -qO- -t1 -T2 "${REPO_URL}" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g')
    URL="https://github.com/EAimTY/tuic/releases/download/${TAG}/${TAG}-${ARCH}-unknown-linux-gnu"
    wget -N --no-check-certificate "${URL}" -O tuic-server
    chmod +x tuic-server
    create_systemd
    create_conf
    run
}

menu() {
  PS3="$(echo -e "请选择 [${plain}1-5${blue}]: ")"
  options=("安装服务" "启动服务" "终止服务" "卸载服务" "退出")
  select option in "${options[@]}"; do
    case $REPLY in
      1) install ;;
      2) run ;;
      3) stop ;;
      4) uninstall ;;
      *) exit 1 ;;
    esac
  done
}

menu
