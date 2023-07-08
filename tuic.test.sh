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
    # Save the private key to the correct location
    cp ~/.acme.sh/${1}_ecc/${1}.key ${workspace}/private_key.pem
    # Install the certificate
    ~/.acme.sh/acme.sh --install-cert -d $1 --ecc --fullchain-file ${workspace}/fullchain.pem --key-file ${workspace}/private_key.pem --reloadcmd "systemctl restart tuic.service"
    [ $? -ne 0 ] && { echo "Dang, couldn't get the certificate." && exit 1; }
}