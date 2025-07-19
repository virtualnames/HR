import random
import os
from datetime import datetime
from OpenSSL import crypto
from collections import defaultdict
from HR.Mutation import mutate_version, mutate_serial_number, mutate_issuer, mutate_validity, mutate_subject
from HR.helpers import write_log1, save_certificate_der_1, save_private_key


class BasicLayer:
    def __init__(self):
        self.key = crypto.PKey()
        self.key.generate_key(crypto.TYPE_RSA, 2048)

    def generate_cert(self, is_ca=False):
        
        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(random.randint(1, 1000000))

        issuer = crypto.X509Name(cert.get_subject())
        issuer.C = "UN"
        issuer.ST = "My ST1"
        issuer.L = "MY Locality1"
        issuer.O = "MY Company1"
        issuer.OU = "My Unit1"
        issuer.CN = "www.mycompany.com"
        cert.set_issuer(issuer)

        cert.set_notBefore(b"190619085559Z")
        cert.set_notAfter(b"290619085559Z")

        subject = cert.get_subject()
        subject.C = "UN"
        subject.ST = "My ST1"
        subject.L = "MY Locality1"
        subject.O = "My Company1"
        subject.OU = "My Unit1"
        subject.CN = "www.mycompany.com"

        cert.set_pubkey(self.key)

        if is_ca:
            basic_constraints = crypto.X509Extension(
                b"basicConstraints", True, b"CA:TRUE"
            )
            cert.add_extensions([basic_constraints])

        cert.sign(self.key, 'sha256')
        return cert

    def load_cert_from_file(self, file_path):
        with open(file_path, "rb") as f:
            cert_data = f.read()
        return crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)


def extract_mutation_value(mutation_details, mutation_type):
    if mutation_type == "version":
        return int(mutation_details.split(":")[1])
    elif mutation_type == "serial_number":
        serial_str = mutation_details.split(":")[1].strip()
        return serial_str[:2]
    elif mutation_type in ["issuer", "subject"]:
        try:
            dict_content = mutation_details.split("{")[1].split("}")[0]
            return dict_content[:7]
        except IndexError:
            return mutation_details[:7]
    elif mutation_type == "validity":
        return mutation_details.split(":")[1]
    return mutation_details


def calculate_unique_ratio(unique_values, total_count):
    if total_count == 0:
        return 0.0
    return len(unique_values) / total_count


def certificate_mutation(
        generate_initial,
        input_folder,
        seed_folder,
        output_folder,
        log_file,
        iteration_count,
        uniqueness_threshold
):

    basic_layer = BasicLayer()

    if generate_initial:
        original_cert = basic_layer.generate_cert()
        save_certificate_der_1(original_cert, directory=seed_folder, filename="Original_cert.der")
        save_private_key(basic_layer.key, directory=seed_folder, filename="Private_key.pem")

        root_cert = basic_layer.generate_cert(is_ca=True)
        save_certificate_der_1(root_cert, directory=seed_folder, filename="RootCA.der")
    else:
        if not os.path.exists(input_folder):
            print(f"Error: The input folder {input_folder} does not exist")
            return

        cert_files = [f for f in os.listdir(input_folder) if f.endswith(('.der', '.cer', '.crt'))]
        if not cert_files:
            print(f"Error: Certificate file not found in input folder {input_folder}")
            return

        first_cert_file = os.path.join(input_folder, cert_files[0])
        original_cert = basic_layer.load_cert_from_file(first_cert_file)

    mutation_functions = [
        (mutate_version, "version"),
        (mutate_serial_number, "serial_number"),
        (mutate_issuer, "issuer"),
        (mutate_validity, "validity"),
        (mutate_subject, "subject")
    ]

    unique_values_tracker = defaultdict(set)
    mutation_counts = defaultdict(int)
    converged_operators = set()

    print(f"\n Mutate...")
    completed_iterations = 0

    while completed_iterations < iteration_count:

        if len(converged_operators) == len(mutation_functions):
            print(f"All mutation operators have converged, terminate iteration prematurely")
            break

        cert_copy = crypto.load_certificate(
            crypto.FILETYPE_ASN1,
            crypto.dump_certificate(crypto.FILETYPE_ASN1, original_cert)
        )

        available_operators = [
            (func, name) for func, name in mutation_functions
            if name not in converged_operators
        ]

        if not available_operators:
            print("No available mutation operator, terminate iteration prematurely")
            break

        mutation_func, mutation_type = random.choice(available_operators)
        mutation_counts[mutation_type] += 1
        completed_iterations += 1

        mutation_details = mutation_func(cert_copy)

        mutation_value = extract_mutation_value(mutation_details, mutation_type)

        unique_values_tracker[mutation_type].add(str(mutation_value))

        unique_ratio = calculate_unique_ratio(
            unique_values_tracker[mutation_type],
            mutation_counts[mutation_type]
        )

        cert_copy.sign(basic_layer.key, 'sha256')

        timestamp = int(datetime.now().timestamp())
        filename = f"Cert_{timestamp}_{completed_iterations}_{mutation_type}.der"

        save_certificate_der_1(cert_copy, directory=output_folder, filename=filename)

        log_entry = f"{filename} {mutation_details} (Unique value ratio: {unique_ratio:.4f})"
        write_log1(log_file, log_entry)

        if unique_ratio < uniqueness_threshold and mutation_type not in converged_operators:
            converged_operators.add(mutation_type)
            print(f"{mutation_type} mutation has converged (unique value ratio: {unique_ratio:. 4f}), this operator will no longer be used")

        print(
            f"  Mutation {completed_iterations}/{iteration_count}: {mutation_type} -> {filename} (Unique value ratio: {unique_ratio:.4f})")
        print(f"  Convergent operator: {list(converged_operators)}")
        print(f"  Available operators: {[name for _, name in available_operators if name not in converged_operators]}")

    print("\n==============")
    for mutation_type, unique_values in unique_values_tracker.items():
        count = mutation_counts[mutation_type]
        if count > 0:
            final_ratio = len(unique_values) / count
            status = "Converged" if mutation_type in converged_operators else "Not converging"
            print(
                f"Mutation {count} times, unique values {len (unique-values)}, unique value ratio {final_ratio:. 4f} ({status})")

    print(f"\n Done! Generate {perfect_iterations} mutation certificates in total")


def get_user_choice(prompt, valid_options):

    while True:
        choice = input(prompt).strip().lower()
        if choice in valid_options:
            return choice
        print(f"Invalid selection, please enter one of {','. join (valid_options)}")


def main():
    
    print("===== BasicLayer =====")

    INPUT_FOLDER = " "
    SEED_FOLDER = " "
    OUTPUT_FOLDER = " "
    LOG_FILE = ""

    generate_choice = get_user_choice(
        "Do you want to generate a new initial certificate?  (y/n) ",
        ["y", "n"]
    )
    generate_initial = generate_choice == "y"

    while True:
        try:
            iteration_count = int(input("Please enter the number of iterations: "))
            if iteration_count > 0:
                break
            print("The number of iterations must be greater than 0!")
        except ValueError:
            print("Please enter a valid number!")

    threshold=0.01

    confirm = get_user_choice(
        "\n Confirm to start? (y/n): ",
        ["y", "n"]
    )
    if confirm != "y":
        print("Cancelled")
        return

    certificate_mutation(
        generate_initial,
        INPUT_FOLDER,
        SEED_FOLDER,
        OUTPUT_FOLDER,
        LOG_FILE,
        iteration_count,
        threshold
    )


if __name__ == "__main__":
    main()