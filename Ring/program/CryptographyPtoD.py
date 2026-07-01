import os
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def pem_to_der(pem_data, filename):
    try:
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        der_data = cert.public_bytes(serialization.Encoding.DER)
        return der_data
    except Exception as e:
        print(f"Error: {filename} {e}")
        return None

def convert_pem_files_to_der(input_folder, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for filename in os.listdir(input_folder):
        if filename.endswith(".pem"):
            pem_path = os.path.join(input_folder, filename)

            try:
                with open(pem_path, "rb") as pem_file:
                    pem_data = pem_file.read()

                der_data = pem_to_der(pem_data, filename)
                if der_data is None:
                    continue

                der_filename = os.path.splitext(filename)[0] + ".der"
                der_path = os.path.join(output_folder, der_filename)

                with open(der_path, "wb") as der_file:
                    der_file.write(der_data)

                print(f"{filename} Converted")
                
            except Exception as e:
                print(f"Error: {filename} {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert PEM certificates to DER format.")
    parser.add_argument('input_folder', help="Input folder containing PEM files")
    parser.add_argument('output_folder', help="Output folder to save DER files")

    args = parser.parse_args()

    convert_pem_files_to_der(args.input_folder, args.output_folder)

