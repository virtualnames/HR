import os
import random
import binascii
import time
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc5280
from collections import defaultdict
from helpers import (
    load_certificate_der3, save_certificate_der3, log_to_file, get_iteration_count
)

CONVERGENCE_THRESHOLD = 0.1
HEX_COMPARE_LENGTH = 3
MIN_SAMPLES = 10


def select_extension():
    print("\n ====== Physical Layer ====== ")
    extensions = [
        ("1", rfc5280.id_ce_authorityKeyIdentifier, "Authority Key Identifier"),
        ("2", rfc5280.id_ce_subjectKeyIdentifier, "Subject Key Identifier"),
        ("3", rfc5280.id_ce_keyUsage, "Key Usage"),
        ("4", rfc5280.id_ce_certificatePolicies, "Certificate Policies"),
        ("5", rfc5280.id_ce_policyMappings, "Policy Mappings"),
        ("6", rfc5280.id_ce_subjectAltName, "Subject Alternative Name"),
        ("7", rfc5280.id_ce_issuerAltName, "Issuer Alternative Name"),
        ("8", rfc5280.id_ce_basicConstraints, "Basic Constraints"),
        ("9", rfc5280.id_ce_nameConstraints, "Name Constraints"),
        ("10", rfc5280.id_ce_policyConstraints, "Policy Constraints"),
        ("11", rfc5280.id_ce_extKeyUsage, "Extended Key Usage"),
        ("12", rfc5280.id_ce_cRLDistributionPoints, "CRL Distribution Points"),
        ("13", rfc5280.id_ce_inhibitAnyPolicy, "Inhibit Any Policy"),
        ("14", rfc5280.id_ce_freshestCRL, "Freshest CRL"),
        ("15", rfc5280.id_pe_authorityInfoAccess, "Authority Information Access"),
        ("16", rfc5280.id_pe_subjectInfoAccess, "Subject Information Access"),
    ]

    for option in extensions:
        print(f"{option[0]}. {option[2]}")

    while True:
        selection = input("\nEnter your selection (single number, 0 to exit): ").strip()
        if not selection.isdigit():
            print("Please enter a valid number!")
            continue

        num = int(selection)
        if 1 <= num <= len(extensions):
            return extensions[num - 1][1], extensions[num - 1][2]
        else:
            print(f"Invalid selection, please enter a number between 1 and {len(extensions)}!")


def select_mutation_method():

    print("\n ====== Mutation method ====== ")
    print("A. Add")
    print("D. Delete")
    print("M. Modify")

    while True:
        method = input("\nEnter your choice (A/D/M): ").strip().upper()
        if method in ["A", "D", "M"]:
            return method
        else:
            print("Invalid selection, please enter A, D, or M!")


def has_target_extension(extensions, target_oid):
    for ext in extensions:
        if ext['extnID'] == target_oid:
            return True
    return False


def calculate_unique_ratio(unique_values, total_count):
    if total_count == 0:
        return 1.0
    return len(unique_values) / total_count


def process_extension(extensions, target_oid, method, log_file, filename, extension_name, cert_tracker):
    for ext in extensions:
        if ext['extnID'] == target_oid:
            original_value = binascii.hexlify(ext['extnValue'].asOctets()).decode()

            if method == "A":
                modified_value = bytearray(binascii.unhexlify(original_value))
                random_index = random.randint(0, len(modified_value) - 1)
                original_byte = modified_value[random_index]
                new_byte = random.randint(0, 255)
                while new_byte == original_byte:
                    new_byte = random.randint(0, 255)
                modified_value[random_index] = new_byte

                new_ext = rfc5280.Extension()
                new_ext['extnID'] = ext['extnID']
                new_ext['critical'] = ext['critical']
                new_ext['extnValue'] = bytes(modified_value)
                extensions.append(new_ext)

                modified_hex = binascii.hexlify(new_ext['extnValue'].asOctets()).decode()
                log_to_file(log_file, filename, extension_name, modified_hex)

            elif method == "D":
                ext['extnValue'] = b''
                modified_hex = binascii.hexlify(ext['extnValue'].asOctets()).decode()
                log_to_file(log_file, filename, extension_name, modified_hex)

            elif method == "M":
                modified_value = bytearray(binascii.unhexlify(original_value))
                num_bytes_to_modify = random.randint(2, len(modified_value))
                modified_indices = set()

                for _ in range(num_bytes_to_modify):
                    random_index = random.randint(0, len(modified_value) - 1)
                    while random_index in modified_indices:
                        random_index = random.randint(0, len(modified_value) - 1)
                    modified_indices.add(random_index)

                    original_byte = modified_value[random_index]
                    new_byte = random.randint(0, 255)
                    while new_byte == original_byte:
                        new_byte = random.randint(0, 255)

                    modified_value[random_index] = new_byte

                ext['extnValue'] = bytes(modified_value)
                modified_hex = binascii.hexlify(ext['extnValue'].asOctets()).decode()
                log_to_file(log_file, filename, extension_name, modified_hex)

                if cert_tracker is not None:
                    new_value_hash = modified_hex[:HEX_COMPARE_LENGTH]
                    cert_tracker['unique_values'].add(new_value_hash)
                    cert_tracker['total_samples'] += 1

                    unique_ratio = calculate_unique_ratio(
                        cert_tracker['unique_values'],
                        cert_tracker['total_samples']
                    )

                    if cert_tracker['total_samples'] >= MIN_SAMPLES:
                        cert_tracker['converged'] = unique_ratio < CONVERGENCE_THRESHOLD

                        if cert_tracker['converged']:
                            status_msg = f"[Converged] Uniqueness ratio: {unique_ratio:.4f}"
                            print(status_msg)
                            log_to_file(log_file, filename, extension_name, status_msg)


def modify_certificate(cert_der, target_oid, method, output_folder, base_name, log_file, extension_name, cert_tracker):
    asn1_cert, _ = decoder.decode(cert_der, asn1Spec=rfc5280.Certificate())
    tbs_certificate = asn1_cert['tbsCertificate']

    if 'extensions' not in tbs_certificate:
        print(f"Warning: Certificate {base_name} does not contain any extensions, skipping processing")
        return None
    extensions = tbs_certificate['extensions']

    if not has_target_extension(extensions, target_oid):
        print(f"Warning: Certificate {base_name} does not contain {extension_name} extension, skipping processing")
        return None

    output_filename = f"{base_name}{method}.der"
    process_extension(extensions, target_oid, method, log_file, output_filename, extension_name, cert_tracker)
    new_cert_der = encoder.encode(asn1_cert)

    return new_cert_der, output_filename


def process_certificates_in_folder(input_folder, output_folder, log_file):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    target_oid, extension_name = select_extension()
    method = select_mutation_method()
    iteration_count = get_iteration_count()

    cert_files = [f for f in os.listdir(input_folder) if f.endswith(".der")]
    total_certs = len(cert_files)

    if total_certs == 0:
        print(f"Error: No DER format certificates found in input folder {input_folder}")
        return

    valid_cert_files = []
    for filename in cert_files:
        input_path = os.path.join(input_folder, filename)
        try:
            cert_der = load_certificate_der3(input_path)
            asn1_cert, _ = decoder.decode(cert_der, asn1Spec=rfc5280.Certificate())
            tbs_certificate = asn1_cert['tbsCertificate']

            if 'extensions' in tbs_certificate:
                extensions = tbs_certificate['extensions']
                if has_target_extension(extensions, target_oid):
                    valid_cert_files.append((filename, cert_der))
        except Exception as e:
            print(f"Error checking certificate {filename}: {str(e)}")

    valid_certs = len(valid_cert_files)
    if valid_certs == 0:
        print(f"Error: No certificates found containing {extension_name} extension")
        return

    print(f"Filtered {valid_certs} certificates containing the {extension_name} extension from {total_certs} certificate files")

    certificate_trackers = {
        filename: {
            'unique_values': set(),
            'total_samples': 0,
            'converged': False
        }
        for filename, _ in valid_cert_files
    } if method == "M" else None

    selection_counts = {filename: 0 for filename, _ in valid_cert_files}

    total_processed = 0

    for i in range(iteration_count):
        index = random.randint(0, valid_certs - 1)
        filename, cert_der = valid_cert_files[index]
        base_name = os.path.splitext(filename)[0]
        selection_counts[filename] += 1

        cert_tracker = certificate_trackers[filename] if method == "M" else None

        progress = f"\rProcessing ({i + 1}/{iteration_count}) - {filename} - Selected {selection_counts[filename]} times"

        if method == "M" and cert_tracker and cert_tracker['total_samples'] > 0:
            unique_ratio = calculate_unique_ratio(
                cert_tracker['unique_values'],
                cert_tracker['total_samples']
            )
            status = "Converged" if cert_tracker['converged'] else "Not Converged"
            progress += f" | Uniqueness ratio: {unique_ratio:.4f} ({status})"

        print(progress, end='')

        try:
            result = modify_certificate(cert_der, target_oid, method, output_folder,
                                        f"{base_name}_{i + 1}", log_file, extension_name, cert_tracker)
            if result:
                new_cert_der, output_filename = result
                save_certificate_der3(os.path.join(output_folder, output_filename), new_cert_der)
                total_processed += 1
        except Exception as e:
            print(f"\n Error processing certificate: {str(e)}")

    print("\n\n ====== Processing Complete ======")

    if method == "M" and certificate_trackers:
        converged_count = 0

        for filename, tracker in certificate_trackers.items():
            if tracker['total_samples'] > 0:
                unique_ratio = calculate_unique_ratio(
                    tracker['unique_values'],
                    tracker['total_samples']
                )
                status = "Converged" if tracker['converged'] else "Not Converged"
                print(
                    f"- Certificate: {filename}: Generated {tracker['total_samples']} mutations, uniqueness ratio {unique_ratio:.4f} ({status})")

                if tracker['converged']:
                    converged_count += 1

        print(f"\nTotal: {converged_count}/{len(certificate_trackers)} certificate extensions have converged")


if __name__ == "__main__":
    print("====== Physical Layer ======")

    INPUT_FOLDER = " "
    OUTPUT_FOLDER = " "
    LOG_FILE = " "

    process_certificates_in_folder(INPUT_FOLDER, OUTPUT_FOLDER, LOG_FILE)