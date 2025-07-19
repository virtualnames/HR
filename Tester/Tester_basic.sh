#!/bin/bash

mkdir -p ./result/basic

# OpenSSL
sh ./program/OpenSSL.sh inputpath outputpath > ./result/basic/OpenSSL.txt 2>&1

# wolfSSL
./DtoP inputpath outputpath > ./result/basic/wolfSSL.txt 2>&1

# GnuTLS
./GnutlsDtoP inputpath outputpath > ./result/basic/GnuTLS.txt 2>&1

# Cryptography
python3 ./CryptographyDtoP.py inputpath outputpath > ./result/basic/Cryptography.txt 2>&1

# Bouncycastle
java ./BouncycastleDtoP inputpath outputpath > ./result/basic/Bouncycastle.txt 2>&1

# Go
go run ./GoDtoP.go -input inputpath -output outputpath > ./result/basic/Go.txt 2>&1




