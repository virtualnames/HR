#!/bin/bash

set -e
LOGFILE="./install_log.txt"
exec > >(tee -i "$LOGFILE") 2>&1

echo "Update apt and install dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential wget curl git unzip cmake pkg-config \
    libtool autoconf automake libssl-dev libtasn1-6-dev \
    openjdk-17-jdk python3 python3-pip python3-venv

# ==================== OpenSSL 3.0.2 ====================
echo "install OpenSSL 3.0.2 ..."
cd /tmp
wget -c https://www.openssl.org/source/openssl-3.0.2.tar.gz
tar -xzf openssl-3.0.2.tar.gz
cd openssl-3.0.2
./Configure --prefix=/usr/local/openssl-3.0.2 --openssldir=/usr/local/openssl-3.0.2 shared
make -j$(nproc)
sudo make install
sudo ln -sf /usr/local/openssl-3.0.2/bin/openssl /usr/bin/openssl-3.0.2

# ==================== GnuTLS 3.8.9 ====================
echo "install GnuTLS 3.8.9 ..."
cd /tmp
sudo apt install aria2
aria2c --check-certificate=false https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.9.tar.xz
tar -xf gnutls-3.8.9.tar.xz
cd gnutls-3.8.9
./configure --prefix=/usr/local/gnutls-3.8.9
make -j$(nproc)
sudo make install
sudo ln -sf /usr/local/gnutls-3.8.9/bin/gnutls-cli /usr/bin/gnutls-3.8.9

# ==================== wolfSSL 5.7.6 ====================
echo "install wolfSSL 5.7.6 ..."
cd /tmp
wget -c https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.tar.gz -O wolfssl-5.7.6.tar.gz
tar -xzf wolfssl-5.7.6.tar.gz
cd wolfssl-5.7.6-stable
./autogen.sh
./configure --prefix=/usr/local/wolfssl-5.7.6 --enable-all
make -j$(nproc)
sudo make install

# ==================== Bouncy Castle JDK 15 ====================
# bcpkix-jdk15on-1.70.jar and bcprov-jdk15on-1.70.jar are available in HR/Ring/Program/lib

# ==================== Go 1.23.2 ====================
echo "install Go 1.23.2 ..."
cd /tmp
wget -c https://go.dev/dl/go1.23.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz
if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
    echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
fi
export PATH=$PATH:/usr/local/go/bin

# ==================== Python dependency libraries  ====================
pip3 install --upgrade pip
pip3 install cryptography==43.0.3 pyopenssl==19.1.0 pyasn1==0.4.8 pyasn1-modules==0.2.8

# ==================== Check ====================
echo "=================Check========================"
echo "OpenSSL:     $(/usr/bin/openssl-3.0.2 version)"
echo "GnuTLS:      $(/usr/bin/gnutls-3.8.9 --version | head -n1)"
echo "wolfSSL:     Please manually check wolfSSL"
echo "Java:        $(java -version 2>&1 | head -n1)"
echo "BouncyCastle: bcpkix-jdk15on-1.70.jar and bcprov-jdk15on-1.70.jar are available in HR/Ring/program/lib"
echo "Go:          $(go version)"
echo "Python dependency libraries:"
python3 -m pip show cryptography pyopenssl pyasn1 pyasn1-modules | grep -E "Name:|Version:"
echo "=============================================="
echo "Installation and checking are complete! Logs are saved in $LOGFILE"
echo "=============================================="

