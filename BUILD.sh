#!/bin/bash

# Build env tested: debian13, wsl-debian
# Remember to check library update // stable?
# Remember to clean /var/

# Usage: bash BUILD.sh [-gh] [-ss] [-sd]
#   -gh: use GitHub proxy while download openssl source
#   -ss: Skip Sync build dir and download src
#   -sd: Skip Dependence software check

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or with sudo."
  exit 1
fi

set -e

if [ "$3" = "-sd" ]; then 
  echo "Skip Dependence software check, run without -sd if any dependence unavailable."
else
  apt update 
  apt upgrade -y
  apt -y install build-essential curl rsync
fi

bpath=$(pwd)/build

if [ "$2" = "-ss" ]; then 
  echo "Skip Sync build dir and download src, run without -sd if src or lib src outdated."
  rsync -a --delete ./src/ $bpath/src
  cd "$bpath"
else
  if [ -d "$bpath" ]; then
    rm -rf $bpath
  fi

  mkdir -p $bpath

  # copy src / build script
  cp -r ./auto $bpath/auto
  cp -r ./conf $bpath/conf
  cp -r ./contrib $bpath/contrib
  cp -r ./docs $bpath/docs
  cp -r ./misc $bpath/misc
  cp -r ./src $bpath/src

  cd "$bpath"

  #download
  curl --progress-bar -L "https://onboardcloud.dl.sourceforge.net/project/pcre/pcre/8.45/pcre-8.45.tar.gz" -o "${bpath}/pcre.tar.gz"
  curl --progress-bar -L "https://zlib.net/zlib-1.3.1.tar.gz" -o "${bpath}/zlib.tar.gz"

  if [ "$1" = "-gh" ]; then 
    curl --progress-bar -L "https://gh-proxy.org/https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz" -o "${bpath}/openssl.tar.gz"
  else
    curl --progress-bar -L "https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz" -o "${bpath}/openssl.tar.gz"
  fi

  # unzip
  tar xzf "pcre.tar.gz"
  tar xzf "zlib.tar.gz"
  tar xzf "openssl.tar.gz"
fi

# build
# following modules are not in use: grpc,mail,cgi,stream
./auto/configure \
  --prefix=/usr/local/nginx \
  --sbin-path=/usr/bin/nginx \
  --conf-path=/usr/local/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --pid-path=/var/run/nginx.pid \
  --lock-path=/var/run/nginx.lock \
  --user=nginx \
  --group=nginx \
  --without-select_module \
  --without-poll_module \
  --with-threads \
  --with-file-aio \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_v3_module \
  --with-http_sub_module \
  --with-http_gunzip_module \
  --with-http_secure_link_module \
  --with-http_degradation_module \
  --without-http_ssi_module \
  --without-http_userid_module \
  --without-http_auth_basic_module \
  --without-http_mirror_module \
  --without-http_autoindex_module \
  --without-http_geo_module \
  --without-http_split_clients_module \
  --without-http_fastcgi_module \
  --without-http_uwsgi_module \
  --without-http_scgi_module \
  --without-http_grpc_module \
  --without-http_memcached_module \
  --without-http_empty_gif_module \
  --without-http_browser_module \
  --http-log-path=/var/log/nginx/access.log \
  --http-client-body-temp-path=/var/cache/nginx/client_temp \
  --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
  --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
  --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
  --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
  --with-cc-opt="-O3 -fPIE -fstack-protector-strong -Wformat -Werror=format-security" \
  --with-ld-opt="-Wl,-Bsymbolic-functions -Wl,-z,relro" \
  --with-pcre="$bpath/pcre-8.45" \
  --with-pcre-jit \
  --with-zlib="$bpath/zlib-1.3.1" \
  --with-openssl="$bpath/openssl-3.6.0" \
  --with-openssl-opt="no-weak-ssl-ciphers no-ssl3 no-shared -DOPENSSL_NO_HEARTBEATS -fstack-protector-strong"
  
make -j12

cp "$bpath/objs/nginx" "$bpath/objs/nginx_"
strip -s $bpath/objs/nginx

echo "see ./build/objs/nginx (strip) and ./build/objs/nginx_ (full)"
echo "  prefix=/usr/local/nginx "
echo "  sbin-path=/usr/bin/nginx "
echo "  conf-path=/usr/local/etc/nginx/nginx.conf "
echo "  error-log-path=/var/log/nginx/error.log "
echo "  pid-path=/var/run/nginx.pid "
echo "  lock-path=/var/run/nginx.lock "
echo "  http-log-path=/var/log/nginx/access.log "
echo "  http-client-body-temp-path=/var/cache/nginx/client_temp "
echo "  http-proxy-temp-path=/var/cache/nginx/proxy_temp "
echo "  http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp "
echo "  http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp "
echo "  http-scgi-temp-path=/var/cache/nginx/scgi_temp "
