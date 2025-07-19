import os
import random
import string
import logging
import ipaddress
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509 import (AuthorityKeyIdentifier)
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding
from cryptography.x509.oid import NameOID

def write_log1(log_file, message):
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    with open(log_file, "a") as f:
        f.write(f"{message}\n")

def setup_logging2_1(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(message)s', filemode='a')

def log_info2_1(cert_name, message):
    logging.info("%s %s", cert_name, message)

def load_certificate_der2_1(file_path):
    with open(file_path, 'rb') as f:
        return crypto.load_certificate(crypto.FILETYPE_ASN1, f.read())

def load_private_key2_1(file_path, passphrase=None):
    with open(file_path, 'rb') as f:
        try:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), passphrase=passphrase)
        except crypto.Error as e:
            raise ValueError(f"Failed to load private key: {e}")

def save_certificate_der_1(cert, directory="certs", filename="certificate.der"):
    if not os.path.exists(directory):
        os.makedirs(directory)
    filepath = os.path.join(directory, filename)
    with open(filepath, "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))

def save_certificate_der2_1(cert, file_path):
    with open(file_path, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))

def setup_logging2_2(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO,
                        format='%(message)s')

def log_info2_2(cert_name, message):
    logging.info("%s %s", cert_name, message)

def load_certificate_der2_2(file_path):
    with open(file_path, 'rb') as f:
        der_data = f.read()
    return x509.load_der_x509_certificate(der_data)

def save_private_key(key, directory="certs", filename="private_key.pem"):
    if not os.path.exists(directory):
        os.makedirs(directory)
    filepath = os.path.join(directory, filename)
    with open(filepath, "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

def load_private_key2_2(file_path, passphrase=None):
    with open(file_path, 'rb') as f:
        key_data = f.read()
    return load_pem_private_key(key_data, password=passphrase)

def save_certificate_der2_2(cert, file_path):
    der_data = cert.public_bytes(encoding=Encoding.DER)
    with open(file_path, 'wb') as f:
        f.write(der_data)

def copy_certificate_data(old_cert, new_cert_builder):
    return new_cert_builder.serial_number(old_cert.serial_number)\
        .not_valid_before(old_cert.not_valid_before)\
        .not_valid_after(old_cert.not_valid_after)\
        .public_key(old_cert.public_key())

def random_authority_key_identifier():
    issuer_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"RandomIssuer-{random.randint(1000, 9999)}"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"RandomOrg-{random.randint(1000, 9999)}")
    ])
    authority_cert_issuer = [x509.DirectoryName(issuer_name)]
    authority_cert_serial_number = random.randint(1, 9999999999)
    key_identifier = os.urandom(20)
    return AuthorityKeyIdentifier(
        key_identifier=key_identifier,
        authority_cert_issuer=authority_cert_issuer,
        authority_cert_serial_number=authority_cert_serial_number
    )

def load_certificate_der3(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

def save_certificate_der3(file_path, cert_der):
    with open(file_path, 'wb') as f:
        f.write(cert_der)

def log_to_file(log_file, filename, extension_name, modified_value):
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"{filename} {extension_name}: {modified_value}\n")

def get_random_str(max_len):
    random_str = ''
    lower_start = ord('a')
    lower_end = ord('z')
    capital_start = ord('A')
    capital_end = ord('Z')
    for i in range(max_len):
        random_str += random.choice(
            [chr(random.randint(lower_start, lower_end)), chr(random.randint(capital_start, capital_end))]
        )
    return random_str

def generate_random_oid():
    prefix = random.choice(["1", "0", "1.1", "2.5", "2.16", "1.3.6", "2.5.29", "1.3.6.1.4.1"])
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_random_mapping_value():
    return f"{random.randint(1, 2)}.{random.randint(0, 32)}.{random.randint(0, 255)}"

def generate_random_string(length):
    characters = string.ascii_letters + string.digits + string.punctuation.replace('.', '').replace('-', '')
    return ''.join(random.choices(characters, k=length))

def generate_random_string0(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))

def generate_random_dns_name():
    return f"DNS:{generate_random_string(5)}.{generate_random_string(5)}.{generate_random_string(3)}"

def generate_random_ip_address():
    return f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_random_ipv6_address():
    return str(ipaddress.IPv6Address(random.getrandbits(128)))

def generate_random_email():
    return f"{generate_random_string(8)}@{generate_random_string(5)}.{generate_random_string(3)}"

def generate_random_uri():
    scheme = random.choice(["http", "https", "ftp"])
    host = generate_random_dns_name()[4:] if random.choice([True, False]) else generate_random_ip_address()
    path = "/".join(generate_random_string(5) for _ in range(random.randint(1, 3)))
    query = f"?{generate_random_string(5)}={generate_random_string(5)}" if random.choice([True, False]) else ""
    return f"{scheme}://{host}/{path}{query}"

def generate_subject_alternative_name():
    return ",".join([
        generate_random_dns_name(),
        f"IP:{generate_random_ip_address()}" if random.choice([True, False]) else f"IP:{generate_random_ipv6_address()}",
        f"email:{generate_random_email()}",
        f"URI:{generate_random_uri()}"
    ])

def generate_issuer_alternative_name():
    return generate_subject_alternative_name()

def generate_random_crl():
    return ",".join([f"URI:http://{generate_random_string(5)}.com/{generate_random_string(5)}.crl" for _ in range(random.randint(1, 2))])

def generate_random_authority_information_access():
    aia = []
    if random.choice([True, False]):
        aia.append(f"OCSP;URI:{generate_random_uri()}")
    if random.choice([True, False]):
        aia.append(f"CA Issuers;URI:{generate_random_uri()}")
    if not aia:
        aia.append(f"OCSP;URI:{generate_random_uri()}")
    return ",".join(aia)

def generate_random_subject_information_access():
    sia = []
    if random.choice([True, False]):
        sia.append(f"caRepository;URI:{generate_random_uri()}")
    if random.choice([True, False]):
        sia.append(f"timeStamping;URI:{generate_random_uri()}")
    if not sia:
        sia.append(f"caRepository;URI:{generate_random_uri()}")
    return ",".join(sia)

def get_iteration_count():
    while True:
        count = input("\nEnter the number of iterations: ").strip()
        if not count.isdigit():
            print("Please enter a valid number!")
            continue

        count = int(count)
        if count <= 0:
            print("Number of iterations must be greater than 0!")
            continue

        return count





