import os
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def der_to_pem(der_data, filename):
    try:
        cert = x509.load_der_x509_certificate(der_data, default_backend())

        pem_data = cert.public_bytes(serialization.Encoding.PEM)

        return pem_data

    except Exception as e:
        print(f"Error: {filename} {e}")
        return None

def convert_der_files_to_pem(input_folder, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for filename in os.listdir(input_folder):
        if filename.endswith(".der"):
            der_path = os.path.join(input_folder, filename)

            try:
                with open(der_path, "rb") as der_file:
                    der_data = der_file.read()

                pem_data = der_to_pem(der_data, filename)

                if pem_data is None:
                    continue

                pem_filename = os.path.splitext(filename)[0] + ".pem"
                pem_path = os.path.join(output_folder, pem_filename)

                with open(pem_path, "wb") as pem_file:
                    pem_file.write(pem_data)

                print(f"{filename} Converted")
                
            except Exception as e:

                print(f"Error: {filename} {e}")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Convert DER certificates to PEM format.")
    parser.add_argument('input_folder', help="Input folder containing DER files")
    parser.add_argument('output_folder', help="Output folder to save PEM files")

    args = parser.parse_args()
    input_folder = args.input_folder
    output_folder = args.output_folder

    convert_der_files_to_pem(input_folder, output_folder)
