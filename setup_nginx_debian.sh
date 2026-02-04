#!/bin/bash

# target: lain@debian13
# Usage: sudo ./setup_nginx_debian.sh [SERVER_DOMAIN]
#   SERVER_DOMAIN: replace example.com in nginx.conf, default nyalake.org

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or with sudo."
  exit 1
fi

set -e

SERVER_DOMAIN="${1:-nyalake.org}"
NGINX_CONF_PREFIX="/usr/local/etc/nginx"
NGINX_BIN="${NGINX_CONF_PREFIX}/nginx"
NGINX_RELEASE_URL="https://github.com/cherry4light/nginx/releases/latest/download/nginx"
NGINX_CONF_RAW="https://raw.githubusercontent.com/cherry4light/nginx/master/conf/nginx.conf"
NGINX_MIME_RAW="https://raw.githubusercontent.com/cherry4light/nginx/master/conf/mime.types"

# =============== AppArmor ===============
# set AppArmor config for nginx (ports, path access etc.)
install_apparmor() {
  if ! command -v aa-status &>/dev/null; then
    echo "Installing AppArmor..."
    apt-get update -qq && apt-get install -y -qq apparmor
  fi
  # Profile name: binary path /usr/local/etc/nginx/nginx -> usr.local.etc.nginx.nginx
  local aa_profile="/etc/apparmor.d/usr.local.etc.nginx.nginx"
  cat > "${aa_profile}" << APPEOF
#include <tunables/global>
# allowed permissions: read config, write log and cache, bind 80/443/4433 etc. ports
/usr/local/etc/nginx/nginx flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  capability net_bind_service,
  capability setgid,
  capability setuid,
  network inet stream,
  network inet6 stream,

  # config read only
  /usr/local/etc/nginx/** r,
  /usr/local/etc/nginx/nginx rix,

  # log and cache
  /var/log/nginx/** w,
  /var/cache/nginx/** rw,

  # runtime
  /proc/*/stat r,
  /run/nginx.pid rw,
}
APPEOF
  apparmor_parser -r "${aa_profile}" 2>/dev/null || true
  echo "AppArmor config for nginx done."
}

# =============== nftables ===============
install_nftables() {
  if ! command -v nft &>/dev/null; then
    echo "Installing nftables..."
    apt-get update -qq && apt-get install -y -qq nftables
  fi
  cat > /etc/nftables.conf << 'NFTEOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    tcp dport 22 accept comment "ssh"
    tcp dport 80 accept comment "http"
    tcp dport 443 accept comment "https"
    tcp dport 4433 accept comment "nginx stream"
  }
  chain forward { type filter hook forward priority filter; policy drop; }
  chain output { type filter hook output priority filter; policy accept; }
}
NFTEOF
  nft -f /etc/nftables.conf
  systemctl enable nftables 2>/dev/null || true
  echo "nftables config done."
}

# =============== nginx user ===============
# least privilege, no login, nginx-specific
add_nginx_user() {
  if ! getent passwd nginx &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin --comment "nginx daemon" nginx
    echo "nginx user added."
  else
    echo "nginx user already exists."
  fi
}

# =============== nginx systemd service ===============
add_nginx_service() {
  cat > /etc/systemd/system/nginx.service << SVCEOF
[Unit]
Description=nginx
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=${NGINX_BIN} -t -p ${NGINX_CONF_PREFIX}
ExecStart=${NGINX_BIN} -p ${NGINX_CONF_PREFIX}
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true
User=nginx
Group=nginx
RuntimeDirectory=nginx

[Install]
WantedBy=multi-user.target
SVCEOF
  systemctl daemon-reload
  echo "nginx systemd service installed."
}

# =============== download nginx binary ===============
download_nginx_binary() {
  mkdir -p "${NGINX_CONF_PREFIX}"
  echo "Downloading nginx binary from ${NGINX_RELEASE_URL} ..."
  wget -q -O "${NGINX_BIN}" "${NGINX_RELEASE_URL}"
  chmod +x "${NGINX_BIN}"
  chown root:root "${NGINX_BIN}"
  echo "nginx binary installed to ${NGINX_BIN}"
}

# =============== create dirs and files nginx use ===============
create_nginx_dirs() {
  # conf-path already created by download step
  mkdir -p /var/log/nginx
  touch /var/log/nginx/error.log /var/log/nginx/access.log \
        /var/log/nginx/stream_error.log /var/log/nginx/stream_access.log
  mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
           /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp \
           /var/cache/nginx/scgi_temp
  chown -R nginx:nginx /var/log/nginx /var/cache/nginx
  # ssl directory (same as ssl path in nginx.conf, changed by sed to NGINX_CONF_PREFIX/ssl)
  mkdir -p "${NGINX_CONF_PREFIX}/ssl"
  chown nginx:nginx "${NGINX_CONF_PREFIX}/ssl"
  echo "nginx dirs and log files created."
}

# =============== download and place nginx.conf ===============
# download config from GitHub and replace example with local address/domain
setup_nginx_conf() {
  echo "Downloading nginx.conf and mime.types..."
  wget -q -O "${NGINX_CONF_PREFIX}/nginx.conf" "${NGINX_CONF_RAW}"
  wget -q -O "${NGINX_CONF_PREFIX}/mime.types" "${NGINX_MIME_RAW}"
  # replace example.com with script parameter/default domain
  sed -i "s/example\.com/${SERVER_DOMAIN}/g" "${NGINX_CONF_PREFIX}/nginx.conf"
  # unify /etc/nginx to conf prefix in config, for single-machine deployment
  sed -i "s|/etc/nginx/|${NGINX_CONF_PREFIX}/|g" "${NGINX_CONF_PREFIX}/nginx.conf"
  # replace git.example.com in proxy_ssl_name with domain name
  sed -i "s|git\.example\.com|git.${SERVER_DOMAIN}|g" "${NGINX_CONF_PREFIX}/nginx.conf"
  chown nginx:nginx "${NGINX_CONF_PREFIX}/nginx.conf" "${NGINX_CONF_PREFIX}/mime.types"
  echo "nginx.conf and mime.types installed (server_name=${SERVER_DOMAIN})."
}

# =============== parse nginx config ===============
test_nginx_config() {
  # if SSL certs not configured, -t may fail; here only do syntax/path check, certs need to be user-provided
  if "${NGINX_BIN}" -t -p "${NGINX_CONF_PREFIX}"; then
    echo "nginx config test OK."
  else
    echo "WARNING: nginx -t failed. Please put SSL certs in ${NGINX_CONF_PREFIX}/ssl/ and run: ${NGINX_BIN} -t -p ${NGINX_CONF_PREFIX}"
  fi
}

# ---------- run ----------
install_apparmor
install_nftables
add_nginx_user
download_nginx_binary
create_nginx_dirs
add_nginx_service
setup_nginx_conf
test_nginx_config

echo ""
echo "========== Success =========="
echo "Please put SSL files in ${NGINX_CONF_PREFIX}/ssl/:"
echo "  - origin.crt, origin.key, origin_ca_rsa_root.pem, git__ca.pem"
echo "Then start nginx manually:"
echo "  systemctl start nginx"
echo "  systemctl enable nginx  # optional"
echo "============================="
