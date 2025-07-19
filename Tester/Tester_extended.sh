#!/bin/bash

mkdir -p ./result/extended

# OpenSSL
sh ./program/OpenSSL.sh inputpath outputpath > ./result/extended/OpenSSL.txt 2>&1

# wolfSSL
./DtoP inputpath outputpath > ./result/extended/wolfSSL.txt 2>&1

# GnuTLS
./GnutlsDtoP inputpath outputpath > ./result/extended/GnuTLS.txt 2>&1

# Cryptography
python3 ./CryptographyDtoP.py inputpath outputpath > ./result/extended/Cryptography.txt 2>&1

# Bouncycastle
java ./BouncycastleDtoP inputpath outputpath > ./result/extended/Bouncycastle.txt 2>&1

# Go
go run ./GoDtoP.go -input inputpath -output outputpath > ./result/extended/Go.txt 2>&1







