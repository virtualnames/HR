import os
import shutil
import re

source_directory = " "       
results_directory = " "      
destination_directory = " "

testers = ['OpenSSL', 'wolfSSL', 'GnuTLS', 'Cryptography', 'Bouncycastle', 'Golang']
direction = "DtoP"

def read_result_file(filename):
    converted_certs = set()
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            for line in f:
                if "Converted" in line:
                    cert_match = re.search(r'Cert\d+\.der', line)
                    if cert_match:
                        converted_certs.add(cert_match.group(0))
    return converted_certs

def main():
    if not os.path.exists(destination_directory):
        os.makedirs(destination_directory)

    all_converted = {}

    for tester in testers:
        result_file = os.path.join(results_directory, f"{tester}_{direction}.txt")
        all_converted[tester] = read_result_file(result_file)
        print(f"{tester} ({direction}): Successfully converted {len(all_converted[tester])} certificates")

    common_converted = set.intersection(*all_converted.values())
    print(f"Number of certificates commonly converted in {direction}: {len(common_converted)}")

    copied_count = 0
    for cert in common_converted:
        source_path = os.path.join(source_directory, cert)
        dest_path = os.path.join(destination_directory, cert)
        if os.path.exists(source_path):
            shutil.copy2(source_path, dest_path)
            copied_count += 1
        else:
            print(f"Not found: {cert}")

    print(f"Successfully copied {copied_count} certificates to {destination_directory}")

if __name__ == "__main__":
    main()
