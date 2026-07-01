# HR

HR uses a Hierarchical Ring (HR) to test certificate format conversions, successfully identifying at least 23 unique issues in different TLS implementations (see `report.md` for details), demonstrating HR's effectiveness.

## Requirements

To configure the environment for HR, run : `$ bash packager.sh`

+ Oracle VM Virtual Box v7.0.12 (https://www.virtualbox.org/)
+ Ubuntu 24.04.1LTS (https://ubuntu.com/)
+ OpenSSL v3.0.2（https://openssl-library.org/）
+ GnuTLS v3.8.9 （https://gnutls.org/）
+ wolfSSL v5.7.6（https://www.wolfssl.com/）
+ Bouncy Castle JDK 15（https://www.bouncycastle.org/）
+ Golang v1.23.2（https://go.dev/）
+ Python packages:
  - cryptography==43.0.3
  - pyOpenSSL==19.1.0
  - pyasn1==0.4.8
  - pyasn1-modules==0.2.8

## Detailed Instructions

Perform testing in a hierarchical order. Each level involves generating test cases, running the Ring test, and preparing seed certificates for the next level.

- `Hierarchical/`: contains test case files generated at each level.
- `Ring/`: contains files used for performing ring tests.
- `Code/`: contains scripts for model building, certificate downloading, and other functionalities.

