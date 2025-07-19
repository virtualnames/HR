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

def fill_json_structure(cert_fields, conversion_results):
    json_structure = {
        "structure": {
            "supported": defaultdict(set),
            "unsupported": defaultdict(set)
        }
    }
    field_status = defaultdict(lambda: defaultdict(set))

    for converter, results in conversion_results.items():
        for cert_name, result in results.items():
            if cert_name in cert_fields:
                for field in cert_fields[cert_name]:
                    if "Converted" in result:
                        field_status[field]["success"].add(converter)
                    else:
                        field_status[field]["failure"].add(converter)

    for field, statuses in field_status.items():
        if statuses["success"] and not statuses["failure"]:
            for converter in statuses["success"]:
                json_structure["structure"]["supported"][converter].add(field)
        elif statuses["failure"] and not statuses["success"]:
            for converter in statuses["failure"]:
                json_structure["structure"]["unsupported"][converter].add(field)
        else:
            for converter in statuses["success"]:
                json_structure["structure"]["supported"][converter].add(field)
            for converter in statuses["failure"]:
                json_structure["structure"]["unsupported"][converter].add(f"{field}: Unrecognized")
    final_json = {
        "structure": {
            key: {conv: sorted(list(fields)) for conv, fields in data.items()}
            for key, data in json_structure["structure"].items()
        }
    }
    return final_json

def main(cert_fields_file, conversion_results_files, struct_json_file):
    cert_fields = parse_certificate_fields(cert_fields_file)
    conversion_results = parse_conversion_results(conversion_results_files)
    json_structure = fill_json_structure(cert_fields, conversion_results)
    
    with open(struct_json_file, "w", encoding="utf-8") as f:
        json.dump(json_structure, f, indent=4, ensure_ascii=False)

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
    struct_json_file = "struct.json"
    
    main(cert_fields_file, conversion_results_files, struct_json_file)

