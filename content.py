import json
import re
from collections import defaultdict

def parse_certificate_fields(cert_fields_file):
    cert_fields = defaultdict(set)
    with open(cert_fields_file, 'r', encoding='utf-8') as f:
        for line in f:
            match = re.match(r'^(\S+)\s+(\S+):', line.strip())
            if match:
                cert_name, field_name = match.groups()
                cert_fields[cert_name].add(field_name.split(":")[0])
    return cert_fields

def parse_conversion_results(conversion_results_files):

    conversion_results = defaultdict(dict)
    for converter, file_path in conversion_results_files.items():
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                match = re.match(r'^(\S+)\s+(Converted|Error: .+)$', line.strip())
                if match:
                    cert_name, result = match.groups()
                    conversion_results[converter][cert_name] = result
    return conversion_results

ERROR_HANDLERS = {
    "Golang": lambda msg: msg.rsplit(":", 1)[-1].strip()
}

def extract_core_error(error_msg, converter):

    handler = ERROR_HANDLERS.get(converter, lambda x: x)
    return handler(error_msg)

def get_field_errors(cert_fields, conversion_results):

    field_errors = defaultdict(lambda: defaultdict(set))
    
    for converter, results in conversion_results.items():
        for cert_name, result in results.items():
            if cert_name in cert_fields and "Error:" in result:
                for field in cert_fields[cert_name]:
                    core_error = extract_core_error(result, converter)
                    error_entry = f"{field}: Error: {core_error}"
                    for field in cert_fields[cert_name]:
                        field_errors[converter][field].add(core_error)
    return field_errors

def fill_content_structure(cert_fields, conversion_results):

    content_json = {"unrecognized": defaultdict(dict)}
    field_errors = get_field_errors(cert_fields, conversion_results)
    
    for converter, fields in field_errors.items():
        for field, errors in fields.items():
            if errors: 
                content_json["unrecognized"][converter][field] = sorted(list(errors))
    return content_json

def main(cert_fields_file, conversion_results_files, content_json_file):

    cert_fields = parse_certificate_fields(cert_fields_file)
    conversion_results = parse_conversion_results(conversion_results_files)
    content_structure = fill_content_structure(cert_fields, conversion_results)
    with open(content_json_file, "w", encoding="utf-8") as f:
        json.dump(content_structure, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":

    cert_fields_file = " "
    conversion_results_files = {
        "OpenSSL": " ",
        "wolfSSL": " ",
        "GnuTLS": " ",
        "Cryptography": " ",
        "Bouncycastle": " "
        "Golang": " ",
    }
    content_json_file = "content.json"
    
    main(cert_fields_file, conversion_results_files, content_json_file)
