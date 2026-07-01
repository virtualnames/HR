import ipaddress
from OpenSSL import crypto
import os
import random
from cryptography import x509
from cryptography.x509 import (PolicyInformation, CertificatePolicies, UserNotice, NoticeReference)

from helpers import generate_random_subject_information_access, generate_random_oid, generate_random_mapping_value, \
    generate_subject_alternative_name, generate_issuer_alternative_name, generate_random_string0, generate_random_crl, \
    generate_random_authority_information_access, random_authority_key_identifier, get_random_str

def mutate_version(cert):
    new_version = random.randint(-1, 10)
    cert.set_version(new_version)
    return f"version:{new_version}"

def mutate_serial_number(cert):
    new_serial = random.randint(1, 2 ** 100 - 1)
    cert.set_serial_number(new_serial)
    return f"serial_number:{new_serial}"

def mutate_issuer(cert):
    issuer = cert.get_issuer()
    changes = {}
    for field in ['C', 'ST', 'L', 'O', 'OU', 'CN']:
        if hasattr(issuer, field):
            random_value = get_random_str(2) if field == 'C' else get_random_str(random.randint(2, 21))
            setattr(issuer, field, random_value)
            changes[field] = random_value
    return f"issuer:{changes}"

def mutate_validity(cert):
    cert.set_notBefore(b"20190619085559Z")
    adj_days = random.randint(-10, -1) * 365
    cert.gmtime_adj_notAfter(adj_days * 24 * 60 * 60)
    new_not_after = cert.get_notAfter().decode('utf-8')
    return f"validity:20190619085559Z to {new_not_after}"

def mutate_subject(cert):
    subject = cert.get_subject()
    changes = {}
    for field in ['C', 'ST', 'L', 'O', 'OU', 'CN']:
        if hasattr(subject, field):
            random_value = get_random_str(2) if field == 'C' else get_random_str(random.randint(2, 21))
            setattr(subject, field, random_value)
            changes[field] = random_value
    return f"subject:{changes}"

def add_aki_extension(cert_builder):
    aki = random_authority_key_identifier()
    critical = random.choice([True, False])
    cert_builder = cert_builder.add_extension(aki, critical=critical)
    aki_info = (f"authority_key_identifier: key_identifier={aki.key_identifier.hex()}, "
                f"authority_cert_issuer={aki.authority_cert_issuer}, "
                f"authority_cert_serial_number={aki.authority_cert_serial_number}, "
                f"critical={critical}")
    return cert_builder, aki_info

def add_subject_key_identifier_extension(cert, cert_name):
    try:
        random_value = os.urandom(16).hex().encode()
        critical_value = random.choice([True, False])
        subject_key_identifier = crypto.X509Extension(
            b"subjectKeyIdentifier",
            critical=critical_value,
            value=random_value
        )
        cert.add_extensions([subject_key_identifier])
        return f"subject_key_identifier:{random_value} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add SKI extension: {str(e)}"

def add_key_usage_extension(cert, cert_name):
    try:
        key_usage_options = [
            "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
            "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
        ]
        selected_usage = random.sample(key_usage_options, k=random.randint(1, len(key_usage_options)))
        usage_value = ",".join(selected_usage)
        critical_value = random.choice([True, False])
        key_usage = crypto.X509Extension(
            b"keyUsage",
            critical=critical_value,
            value=usage_value.encode('utf-8')
        )
        cert.add_extensions([key_usage])
        return f"key_usage:{usage_value} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add KeyUsage extension: {str(e)}"

def add_certificate_policies_extension(cert_builder):
    policy_identifiers = [
        ("2.5.29.32.0", "Any Policy"),
        ("2.23.140.1.2.1", "Domain Validated"),
        ("1.3.6.1.4.1.34697.2.1", "Example Policy"),
        ("1.2.3.4.5.6.7", "Another Example Policy")
    ]
    policies = []
    for policy_id, policy_name in random.sample(policy_identifiers, k=random.randint(1, len(policy_identifiers))):
        policy_qualifiers = []
        if random.choice([True, False]):
            cps_uri = f"https://example.com/cps/{policy_name.lower().replace(' ', '-')}"
            policy_qualifiers.append(cps_uri)
        if random.choice([True, False]):
            notice_ref = NoticeReference(
                organization="Example Org",
                notice_numbers=[random.randint(1, 100)]
            ) if random.choice([True, False]) else None
            user_notice = UserNotice(
                notice_reference=notice_ref,
                explicit_text=f"This certificate follows the {policy_name} policy."
            )
            policy_qualifiers.append(user_notice)

        policy = PolicyInformation(
            policy_identifier=x509.ObjectIdentifier(policy_id),
            policy_qualifiers=policy_qualifiers if policy_qualifiers else None
        )
        policies.append(policy)

    cert_policies = CertificatePolicies(policies)
    critical = random.choice([True, False])
    cert_builder = cert_builder.add_extension(cert_policies, critical=critical)
    policy_str = ', '.join(
        [f"{policy.policy_identifier.dotted_string} (CPS: {'Yes' if any(isinstance(q, str) for q in policy.policy_qualifiers or []) else 'No'}, "
         f"UserNotice: {'Yes' if any(isinstance(q, UserNotice) for q in policy.policy_qualifiers or []) else 'No'})"
         for policy in policies])
    policies_info = f"certificate_policies: {policy_str} (critical={critical})"
    return cert_builder, policies_info

def add_policy_mappings_extension(cert, cert_name):
    try:
        oid = generate_random_oid()
        mapping_value = generate_random_mapping_value()
        mappings = f"{oid}:{mapping_value}"
        critical_value = random.choice([True, False])

        policy_mappings_extension = crypto.X509Extension(
            b"policyMappings",
            critical=critical_value,
            value=mappings.encode('ascii')
        )
        cert.add_extensions([policy_mappings_extension])
        return f"policy_mappings:{mappings} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add PolicyMappings extension: {str(e)}"

def add_subject_alternative_name_extension(cert, cert_name):
    try:
        alt_names = generate_subject_alternative_name()
        critical_value = random.choice([True, False])
        san = crypto.X509Extension(
           b"subjectAltName",
           critical=critical_value,
           value=alt_names.encode()
        )
        cert.add_extensions([san])
        return f"subject_alternative_name:{alt_names} (critical={critical_value})"

    except Exception as e:
        return f"Failed to add SAN extension: {str(e)}"

def add_issuer_alternative_name_extension(cert, cert_name):
    try:
        alt_names = generate_issuer_alternative_name()
        critical_value = random.choice([True, False])
        ian = crypto.X509Extension(
           b"issuerAltName",
           critical=critical_value,
           value=alt_names.encode()
        )
        cert.add_extensions([ian])
        return f"issuer_alternative_name:{alt_names} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add IAN extension: {str(e)}"

def add_basic_constraints_extension(cert, cert_name):
    try:
        ca_value = random.choice([True, False])
        include_pathlen = random.choice([True, False])
        if ca_value and include_pathlen:
            pathlen_value = random.randint(0, 5)
            basic_constraints_value = f"CA:TRUE, pathlen:{pathlen_value}"
        elif ca_value and not include_pathlen:
            basic_constraints_value = "CA:TRUE"
        elif not ca_value and include_pathlen:
            pathlen_value = random.randint(0, 5)
            basic_constraints_value = f"CA:FALSE, pathlen:{pathlen_value}"
        else:
            basic_constraints_value = "CA:FALSE"
        critical_value = random.choice([True, False])
        basic_constraints = crypto.X509Extension(
            b"basicConstraints",
            critical=critical_value,
            value=basic_constraints_value.encode('utf-8')
        )
        cert.add_extensions([basic_constraints])
        return f"basic_constraints:{basic_constraints_value} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add BC extension: {str(e)}"

def add_name_constraints_extension(cert, cert_name):
    def generate_email():
        username = generate_random_string0(random.randint(3, 12))
        domain = generate_random_string0(random.randint(3, 10))
        tld = generate_random_string0(random.randint(2, 5))
        return f"{username}.{domain}.{tld}"

    def generate_dns():
        subdomain_length = random.randint(3, 10)
        domain_length = random.randint(3, 10)
        tld_length = random.randint(2, 5)
        subdomain = generate_random_string0(subdomain_length)
        domain = generate_random_string0(domain_length)
        tld = generate_random_string0(tld_length)
        return f"{subdomain}.{domain}.{tld}"

    def generate_random_ip_with_subnet():
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        #subnet_mask = f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        subnet_mask = "255.255.255.0"
        return f"{ip}/{subnet_mask}"

    def generate_random_ipv4():
        ip = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
        subnet = random.randint(0, 32)
        network = ipaddress.IPv4Network(f"{ip}/{subnet}", strict=False)
        return network.with_prefixlen

    permitted_constraints = [
        f"permitted;email:{generate_email()}",
        f"permitted;DNS:{generate_dns()}",
        f"permitted;IP:{generate_random_ip_with_subnet()}"
    ]

    excluded_constraints = [
        f"excluded;email:{generate_email()}",
        f"excluded;DNS:{generate_dns()}",
        f"excluded;IP:{generate_random_ip_with_subnet()}"
    ]

    constraints = ",".join(permitted_constraints) + "," + ",".join(excluded_constraints)
    critical_value = random.choice([True, False])

    try:
        name_constraints = crypto.X509Extension(
            b"nameConstraints",
            critical=critical_value,
            value=constraints.encode()
        )
        cert.add_extensions([name_constraints])

        return f"name_constraints:{constraints} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add NC extension: {str(e)}"

def add_policy_constraints_extension(cert, cert_name):
    try:
        require_explicit_policy = random.randint(-1, 10)
        inhibit_policy_mapping = random.randint(-1, 10)
        critical_value = random.choice([True, False])
        constraints = f"requireExplicitPolicy:{require_explicit_policy},inhibitPolicyMapping:{inhibit_policy_mapping}"
        policy_constraints = crypto.X509Extension(
            b"policyConstraints",
            critical=critical_value,
            value=constraints.encode()
        )
        cert.add_extensions([policy_constraints])
        return f"policy_constraints:requireExplicitPolicy={require_explicit_policy},inhibitPolicyMapping={inhibit_policy_mapping} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add PC extension: {str(e)}"

def add_extended_key_usage_extension(cert, cert_name):
    try:
        ext_key_usage_options = [
            "serverAuth", "clientAuth", "codeSigning", "emailProtection",
            "timeStamping", "OCSPSigning", "ipsecIKE"
        ]
        selected_ext_usage = random.sample(ext_key_usage_options, k=random.randint(1, len(ext_key_usage_options)))
        ext_usage_value = ",".join(selected_ext_usage)
        critical_value = random.choice([True, False])
        ext_key_usage = crypto.X509Extension(
            b"extendedKeyUsage",
            critical=critical_value,
            value=ext_usage_value.encode('utf-8')
        )
        cert.add_extensions([ext_key_usage])
        return f"extended_key_usage:{ext_usage_value} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add EKU extension: {str(e)}"

def add_crl_distribution_points_extension(cert, cert_name):
    try:
        crl_dps = generate_random_crl()
        critical_value = random.choice([True, False])
        crl_dp = crypto.X509Extension(
            b"crlDistributionPoints",
            critical=critical_value,
            value=crl_dps.encode()
        )
        cert.add_extensions([crl_dp])
        return f"crl_distribution_points:{crl_dps} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add CrlDP extension: {str(e)}"

def add_inhibit_any_policy_extension(cert, cert_name):
    try:
        inhibit_any = str(random.randint(-1, 10))
        critical_value = random.choice([True, False])
        inhibit_any_extension = crypto.X509Extension(
            b"inhibitAnyPolicy",
            critical=critical_value,
            value=inhibit_any.encode()
        )
        cert.add_extensions([inhibit_any_extension])
        return f"inhibit_any_policy:{inhibit_any} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add IAP extension: {str(e)}"

def add_freshest_crl_extension(cert, cert_name):
    try:
        f_crl = generate_random_crl()
        critical_value = random.choice([True, False])
        freshest_crl = crypto.X509Extension(
            b"freshestCRL",
            critical=critical_value,
            value=f_crl.encode()
        )
        cert.add_extensions([freshest_crl])
        return f"freshest_crl:{f_crl} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add FCrl extension: {str(e)}"

def add_authority_information_access_extension(cert, cert_name):
    try:
        aia_value = generate_random_authority_information_access()
        critical_value = random.choice([True, False])

        aia_extension = crypto.X509Extension(
            b"authorityInfoAccess",
            critical=critical_value,
            value=aia_value.encode()
        )
        cert.add_extensions([aia_extension])
        return f"authority_information_access:{aia_value} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add AIA extension: {str(e)}"

def add_subject_information_access_extension(cert):
    try:
        sia_value = generate_random_subject_information_access()
        critical_value = random.choice([True, False])
        ext = crypto.X509Extension(b"subjectInfoAccess", critical=critical_value, value=sia_value.encode())
        cert.add_extensions([ext])
        return f"subject_information_access:{sia_value} (critical={critical_value})"
    except Exception as e:
        return f"Failed to add SIA extension: {str(e)}"

