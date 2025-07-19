import os
import re
import random
import time
import hashlib
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from helpers import (
    setup_logging2_1,
    load_certificate_der2_1,
    load_private_key2_1,
    save_certificate_der2_1,
    log_info2_1, copy_certificate_data, load_certificate_der2_2, save_certificate_der2_2, log_info2_2, \
    load_private_key2_2, setup_logging2_2, get_iteration_count
)
from Mutation import (
    add_subject_information_access_extension,
    add_certificate_policies_extension,
    add_subject_key_identifier_extension,
    add_key_usage_extension,
    add_policy_mappings_extension,
    add_subject_alternative_name_extension,
    add_issuer_alternative_name_extension,
    add_basic_constraints_extension,
    add_name_constraints_extension,
    add_policy_constraints_extension,
    add_extended_key_usage_extension,
    add_crl_distribution_points_extension,
    add_inhibit_any_policy_extension,
    add_freshest_crl_extension,
    add_authority_information_access_extension,
    add_aki_extension
)

def display_extensions_menu():
 
    print("====== ExtendedLayer ======")
    print("\nPlease select the certificate extension to add (enter a single number, enter 0 to exit):")
    extensions = [
        ("1", "Authority Key Identifier", add_aki_extension, "process_certificates2"),
        ("2", "Subject Key Identifier", add_subject_key_identifier_extension, "process_certificates"),
        ("3", "Key Usage", add_key_usage_extension, "process_certificates"),
        ("4", "Certificate Policies", add_certificate_policies_extension, "process_certificates2"),
        ("5", "Policy Mappings", add_policy_mappings_extension, "process_certificates"),
        ("6", "Subject Alternative Name", add_subject_alternative_name_extension, "process_certificates"),
        ("7", "Issuer Alternative Name", add_issuer_alternative_name_extension, "process_certificates"),
        ("8", "Basic Constraints", add_basic_constraints_extension, "process_certificates"),
        ("9", "Name Constraints", add_name_constraints_extension, "process_certificates"),
        ("10", "Policy Constraints", add_policy_constraints_extension, "process_certificates"),
        ("11", "Extended Key Usage", add_extended_key_usage_extension, "process_certificates"),
        ("12", "CRL Distribution Points", add_crl_distribution_points_extension, "process_certificates"),
        ("13", "Inhibit Any Policy", add_inhibit_any_policy_extension, "process_certificates"),
        ("14", "Freshest CRL", add_freshest_crl_extension, "process_certificates"),
        ("15", "Authority Information Access", add_authority_information_access_extension, "process_certificates"),
        ("16", "Subject Information Access", add_subject_information_access_extension, "process_certificates")
    ]

    for option in extensions:
        print(f"{option[0]}. {option[1]}")

    while True:
        selection = input("\nPlease enter your selection: ").strip()
        if selection == '0':
            return None, None

        if not selection.isdigit():
            print("Please enter a valid number!")
            continue

        num = int(selection)
        if 1 <= num <= len(extensions):
            ext_func = extensions[num - 1][2]
            proc_func_name = extensions[num - 1][3]
            return ext_func, proc_func_name
        else:
            print(f"Invalid selection. Please enter a number between 1 and {len(extensions)}!")


def extract_mutation_value(info, ext_name):
 
    if ext_name == "Authority Key Identifier":
        if "key_identifier" in info:
            key_id = info.split("key_identifier=")[1].split(",")[0]
            return key_id[:2]
        return info 
    elif ext_name == "Subject Key Identifier":
        if "subject_key_identifier" in info:）
            ski_hex = info.split(":")[1].split(" ")[0]
            return ski_hex[:4]
        return info
    elif ext_name == "Key Usage":
        if "key_usage" in info:
            usages = info.split(":")[1].split(" (")[0]
            sorted_usages = ",".join(sorted(usages.split(",")))
            return sorted_usages[:7]
        return info
    elif ext_name == "Certificate Policies":
        if "certificate_policies" in info:
            try:
                oids = re.findall(r'(\b\d+(?:\.\d+)*\b)\s*\(', info)
                return ",".join(oids)
            except Exception as e:
                print(f"Error in Certificate Policies: {e}")
                return info
        return info
    elif ext_name == "Policy Mappings":
        if "policy_mappings" in info:
            try:
                mappings_str = info.split(":")[1].split(" (")[0].strip()
                oid_pairs = []
                for pair in mappings_str.split(", "):
                    if ':' in pair:
                        source, target = pair.split(':')）
                        source_simplified = ".".join(source.split('.')[:3])
                        target_simplified = ".".join(target.split('.')[:3])
                        oid_pairs.append(f"{source_simplified}:{target_simplified}")
                return ",".join(sorted(oid_pairs)) if oid_pairs else None
            except Exception as e:
                print(f"Error in Policy Mappings: {e}")
                return None
        return None
    elif ext_name == "Subject Alternative Name":
        if "subject_alternative_name" in info:
            sans = info.split(":")[1].split(" (")[0]
            sorted_sans = ",".join(sorted(sans.split(",")))
            return sorted_sans
        return info
    elif ext_name == "Issuer Alternative Name":
        if "issuer_alternative_name" in info:
            ians = info.split(":")[1].split(" (")[0]
            sorted_ians = ",".join(sorted(ians.split(",")))
            return sorted_ians
        return info
    elif ext_name == "Basic Constraints":
        if "basic_constraints" in info:
            bc = info.split(":")[1].split(" (")[0]
            normalized = bc.replace(" ", "").lower()
            return normalized
        return info
    elif ext_name == "Name Constraints":
        if "name_constraints" in info:
            nc = info.split(":")[1].split(" (")[0]
            types = [part.split(";")[0] for part in nc.split(",")]
            return ",".join(sorted(types))
        return info
    elif ext_name == "Policy Constraints":
        if "policy_constraints" in info:
            pc = info.split(":")[1].split(" (")[0]
            params = [p.split("=")[0] for p in pc.split(",")]
            return ",".join(sorted(params))
        return info
    elif ext_name == "Extended Key Usage":
        if "extended_key_usage" in info:
            usages = info.split(":")[1].split(" (")[0]
            sorted_usages = ",".join(sorted(usages.split(",")))
            return sorted_usages[:7]
        return info
    elif ext_name == "CRL Distribution Points":
        if "crl_distribution_points" in info:
            crl_dps = info.split(":")[1].split(" (")[0]
            domains = []
            for dp in crl_dps.split(","):
                if "://" in dp:
                    domain = dp.split("://")[1].split("/")[0]
                    domains.append(domain)
            return ",".join(sorted(domains))
        return info
    elif ext_name == "Inhibit Any Policy":
        if "inhibit_any_policy" in info:
            depth = info.split(":")[1].split(" (")[0]
            return depth
        return info
    elif ext_name == "Freshest CRL":
        if "freshest_crl" in info:
            crl = info.split(":")[1].split(" (")[0]
            if "://" in crl:
                domain = crl.split("://")[1].split("/")[0]
                return domain
            return crl
        return info
    elif ext_name == "Authority Information Access":
        if "authority_information_access" in info:
            aia = info.split(":")[1].split(" (")[0]
            if "://" in aia:
                domain = aia.split("://")[1].split("/")[0]
                return domain
            return aia
        return info
    elif ext_name == "Subject Information Access":
        if "subject_information_access" in info:
            sia = info.split(":")[1].split(" (")[0]
            if "://" in sia:
                domain = sia.split("://")[1].split("/")[0]
                return domain
            return sia
        return None
    else:
        return str(info)
def calculate_unique_ratio(unique_values, total_count):
    if total_count == 0:
        return 0.0
    return len(unique_values) / total_count

def process_certificates(input_dir, root_cert_path, key_path, output_dir, log_file, num_certificates,
                         key_passphrase=None, ext_func=None, ext_name=None, threshold=0.1):
    setup_logging2_1(log_file)
    os.makedirs(output_dir, exist_ok=True)
    private_key = load_private_key2_1(key_path, passphrase=key_passphrase)
    root_cert = load_certificate_der2_1(root_cert_path)
    existing_certs = [os.path.join(input_dir, f) for f in os.listdir(input_dir)
                      if f.lower().endswith(('.der', '.cer'))]

    if not existing_certs:
        print(f"Error: No DER format certificate files found in the input directory {input_dir}!")
        return
    unique_values = set()
    mutation_counts = 0
    converged = False
    import inspect
    sig = inspect.signature(ext_func)
    requires_filename = len(sig.parameters) > 1

    for i in range(num_certificates):
        if converged:
            print(f"Converged, terminating generation early")
            break
        input_path = random.choice(existing_certs)
        base_name = os.path.splitext(os.path.basename(input_path))[0]
        try:
            old_cert = load_certificate_der2_1(input_path)
            new_cert = crypto.X509()
            new_cert.set_version(2)
            new_cert.set_serial_number(old_cert.get_serial_number())
            new_cert.set_notBefore(b"190619085559Z")
            new_cert.set_notAfter(b"290619085559Z")
            new_cert.set_pubkey(old_cert.get_pubkey())
            
            subject = new_cert.get_subject()
            subject.C = "UN"
            subject.ST = "My ST1"
            subject.L = "MY Locality1"
            subject.O = "My Company1"
            subject.OU = "My Unit1"
            subject.CN = "www.mycompany1.com"
            new_cert.set_issuer(root_cert.get_subject())

            timestamp = int(time.time())
            output_filename = f"Cert{timestamp}{i + 1}.der"
            output_path = os.path.join(output_dir, output_filename)

            if requires_filename:
                info = ext_func(new_cert, output_filename)
            else:
                info = ext_func(new_cert)
                
            mutation_value = extract_mutation_value(info, ext_name)
            unique_values.add(mutation_value)
            mutation_counts += 1

            unique_ratio = calculate_unique_ratio(unique_values, mutation_counts)
            converged = unique_ratio < threshold
            new_cert.sign(private_key, 'sha256')
            save_certificate_der2_1(new_cert, output_path)
            log_info2_1(output_filename, f"{info} (Unique value ratio: {unique_ratio:.4f})")

            if converged:
                print(f"The {ext_name} extension has converged (unique value ratio: {unique_ratio:.4f}), stopping generation")
        except Exception as e:
            log_info2_1(base_name, f"Processing error: {str(e)}")
            print(f"Error processing certificate {base_name}: {e}")

    final_ratio = calculate_unique_ratio(unique_values, mutation_counts)
    status = "Converged" if converged else "Not converged"
    print(f"\n[Batch Processing Statistics] {ext_name} Extension: Generated {mutation_counts} certificates, {len(unique_values)} unique values, uniqueness ratio {final_ratio:.4f} ({status})")

def process_certificates2(input_cert_path, key_path, root_cert_path, output_dir, log_file,
                          mutation_count, ext_func=None,ext_name=None, threshold=0.1):
    setup_logging2_2(log_file)
    os.makedirs(output_dir, exist_ok=True)
    private_key = load_private_key2_2(key_path)
    root_cert = load_certificate_der2_2(root_cert_path)
    unique_values = set()
    mutation_counts = 0
    converged = False
    
    import inspect
    sig = inspect.signature(ext_func)
    requires_filename = len(sig.parameters) > 1

    try:
        old_cert = load_certificate_der2_2(input_cert_path)
        base_timestamp = int(time.time())

        for i in range(mutation_count):
            if converged:
                print(f"Converged, terminating generation early")
                break
            new_cert_builder = x509.CertificateBuilder()
            new_cert_builder = copy_certificate_data(old_cert, new_cert_builder)

            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "UN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "My ST1"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "MY Locality1"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company1"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "My Unit1"),
                x509.NameAttribute(NameOID.COMMON_NAME, "www.mycompany1.com")
            ])
            new_cert_builder = new_cert_builder.subject_name(subject)
            new_cert_builder = new_cert_builder.issuer_name(root_cert.issuer)

            output_filename = f'Cert{base_timestamp}{i + 1}.der'

            if requires_filename:
                if ext_func in (add_aki_extension, add_certificate_policies_extension):
                    new_cert_builder, info = ext_func(new_cert_builder)
                else:
                    new_cert_builder, info = ext_func(new_cert_builder, output_filename)
            else:
                if ext_func in (add_aki_extension, add_certificate_policies_extension):
                    new_cert_builder, info = ext_func(new_cert_builder)
                else:
                    new_cert_builder, info = ext_func(new_cert_builder)

            mutation_value = extract_mutation_value(info, ext_name)
            unique_values.add(mutation_value)
            mutation_counts += 1

            unique_ratio = calculate_unique_ratio(unique_values, mutation_counts)
            converged = unique_ratio < threshold

            new_cert = new_cert_builder.sign(private_key, hashes.SHA256())
            output_path = os.path.join(output_dir, output_filename)
            save_certificate_der2_2(new_cert, output_path)

            log_info2_2(output_filename, f"{info} (Unique value ratio: {unique_ratio:.4f})")
            if converged:
                print(f"[Warning] The {ext_name} extension has converged (unique value ratio: {unique_ratio:.4f}), stopping generation")
    except Exception as e:
        log_info2_1("Certificate processing error", str(e))
        print(f"Error processing certificate: {e}")
    final_ratio = calculate_unique_ratio(unique_values, mutation_counts)
    status = "Converged" if converged else "Not Converged"
    print(
        f"\n{ext_name} Extension: Generated {mutation_counts} certificates, {len(unique_values)} unique values, uniqueness ratio {final_ratio:.4f} ({status})"


if __name__ == "__main__":
    print("====== ExtendedLayer ======")

    INPUT_DIR = " "
    INPUT_CERT_PATH = " "
    ROOT_CERT_PATH = " "
    KEY_PATH = " "
    OUTPUT_DIR = " "
    LOG_FILE = " "
    KEY_PASSPHRASE = None
    UNIQUENESS_THRESHOLD = 0.01

    ext_func, proc_func_name = display_extensions_menu()
    if not ext_func:
        print("Operation cancelled, program exiting.")
        exit()
    extensions = [
        ("1", "Authority Key Identifier", add_aki_extension, "process_certificates2"),
        ("2", "Subject Key Identifier", add_subject_key_identifier_extension, "process_certificates"),
        ("3", "Key Usage", add_key_usage_extension, "process_certificates"),
        ("4", "Certificate Policies", add_certificate_policies_extension, "process_certificates2"),
        ("5", "Policy Mappings", add_policy_mappings_extension, "process_certificates"),
        ("6", "Subject Alternative Name", add_subject_alternative_name_extension, "process_certificates"),
        ("7", "Issuer Alternative Name", add_issuer_alternative_name_extension, "process_certificates"),
        ("8", "Basic Constraints", add_basic_constraints_extension, "process_certificates"),
        ("9", "Name Constraints", add_name_constraints_extension, "process_certificates"),
        ("10", "Policy Constraints", add_policy_constraints_extension, "process_certificates"),
        ("11", "Extended Key Usage", add_extended_key_usage_extension, "process_certificates"),
        ("12", "CRL Distribution Points", add_crl_distribution_points_extension, "process_certificates"),
        ("13", "Inhibit Any Policy", add_inhibit_any_policy_extension, "process_certificates"),
        ("14", "Freshest CRL", add_freshest_crl_extension, "process_certificates"),
        ("15", "Authority Information Access", add_authority_information_access_extension, "process_certificates"),
        ("16", "Subject Information Access", add_subject_information_access_extension, "process_certificates")
    ]
    ext_name = next((ext[1] for ext in extensions if ext[2] == ext_func), "Unknown extension")

    NUM_CERTIFICATES = get_iteration_count()

    if proc_func_name == "process_certificates":
        process_certificates(INPUT_DIR, ROOT_CERT_PATH, KEY_PATH, OUTPUT_DIR, LOG_FILE,
                             NUM_CERTIFICATES, KEY_PASSPHRASE, ext_func, ext_name, UNIQUENESS_THRESHOLD)
    elif proc_func_name == "process_certificates2":
        process_certificates2(INPUT_CERT_PATH, KEY_PATH, ROOT_CERT_PATH, OUTPUT_DIR, LOG_FILE,
                              NUM_CERTIFICATES, ext_func, ext_name, UNIQUENESS_THRESHOLD)

    print("\n====== Completed ======")
