#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <input_folder> <output_folder>"
    exit 1
fi

input_folder="$1"
output_folder="$2"

mkdir -p "$output_folder"

for pem_file in "$input_folder"/*.pem; do
    if [ -f "$pem_file" ]; then
        pem_filename=$(basename "$pem_file")
        der_filename="${pem_filename%.*}.der"
        der_output_path="$output_folder/$der_filename"

        if ! output=$(openssl x509 -inform PEM -outform DER -in "$pem_file" -out "$der_output_path" 2>&1); then

            error_message=$(echo "$output" | grep -i 'unable to load certificate\|could not read certificate\|error' | tail -n 1)
            echo "$pem_filename Error: $error_message"
        else
            echo "$pem_filename Converted"
        fi
    fi
done

