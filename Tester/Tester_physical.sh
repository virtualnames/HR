#!/bin/bash

mkdir -p ./result/physical

# OpenSSL
sh ./program/OpenSSL.sh inputpath outputpath > ./result/physical/OpenSSL.txt 2>&1

# wolfSSL
./DtoP inputpath outputpath > ./result/physical/wolfSSL.txt 2>&1

# GnuTLS
./GnutlsDtoP inputpath outputpath > ./result/physical/GnuTLS.txt 2>&1

# Cryptography
python3 ./CryptographyDtoP.py inputpath outputpath > ./result/physical/Cryptography.txt 2>&1

# Bouncycastle
java ./BouncycastleDtoP inputpath outputpath > ./result/physical/Bouncycastle.txt 2>&1

# Go
go run ./GoDtoP.go -input inputpath -output outputpath > ./result/physical/Go.txt 2>&1







