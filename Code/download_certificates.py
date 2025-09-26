#-*- Coding: utf-8 -*-
#Prerequisite: Use Zmap（ https://zmap.io ）Before running this script, scan port 443 and save the resulting IP address to a file named ips.csv.
import sys
import ssl
import socket
import OpenSSL.crypto as crypto
import time
def mailsmsPoC(url,target_folder):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((url, 443))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        s = context.wrap_socket(s, server_hostname=url)
        cert = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert)
        with open(target_folder+url+'.der', 'wb') as f:
            f.write(cert)
        s.close()

if __name__=="__main__":
    filepath = './ips.csv'
    target_folder = './der/'
    file = open(filepath, 'r')
    for f in file.readlines():
        url = f.strip('\r\n')
        try:
            url = f.strip('\r\n')
            mailsmsPoC(url,target_folder)
            time.sleep(0.01)
        except:
            print("time out")
            continue

