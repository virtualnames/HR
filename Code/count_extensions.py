import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

EXT_OIDS = {
    "authorityKeyIdentifier": x509.OID_AUTHORITY_KEY_IDENTIFIER,
    "subjectKeyIdentifier": x509.OID_SUBJECT_KEY_IDENTIFIER,
    "keyUsage": x509.OID_KEY_USAGE,
    "certificatePolicies": x509.OID_CERTIFICATE_POLICIES,
    "policyMappings": x509.ObjectIdentifier("2.5.29.33"),
    "subjectAltName": x509.OID_SUBJECT_ALTERNATIVE_NAME,
    "issuerAltName": x509.OID_ISSUER_ALTERNATIVE_NAME,
    "basicConstraints": x509.OID_BASIC_CONSTRAINTS,
    "nameConstraints": x509.OID_NAME_CONSTRAINTS,
    "policyConstraints": x509.OID_POLICY_CONSTRAINTS,
    "extendedKeyUsage": x509.OID_EXTENDED_KEY_USAGE,
    "crlDistributionPoints": x509.OID_CRL_DISTRIBUTION_POINTS,
    "inhibitAnyPolicy": x509.OID_INHIBIT_ANY_POLICY,
    "freshestCRL": x509.OID_FRESHEST_CRL,
    "authorityInfoAccess": x509.OID_AUTHORITY_INFORMATION_ACCESS,
    "subjectInfoAccess": x509.ObjectIdentifier("1.3.6.1.5.5.7.1.11"),
}

def load_cert(path):
    with open(path, "rb") as f:
        data = f.read()
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except Exception:
        return x509.load_pem_x509_certificate(data, default_backend())

def scan_certificates(folder):
    stats = {name: 0 for name in EXT_OIDS.keys()}
    total = 0

    for file in os.listdir(folder):
        if not (file.endswith(".der") or file.endswith(".cer") or file.endswith(".pem")):
            continue
        path = os.path.join(folder, file)
        try:
            cert = load_cert(path)
            total += 1
            for name, oid in EXT_OIDS.items():
                try:
                    cert.extensions.get_extension_for_oid(oid)
                    stats[name] += 1
                except x509.ExtensionNotFound:
                    pass
        except Exception as e:
            print(f"[!] Failed to parse {file}: {e}")

    return stats, total

if __name__ == "__main__":
    FOLDER = " "
    stats, total = scan_certificates(FOLDER)
    print(f"\nScanned {total} certificates\n")
    for name, count in stats.items():
        print(f"{name:25} : {count}/{total}")

