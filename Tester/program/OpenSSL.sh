#!/bin/bash

# Check if both input and output folders are provided as arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <input_folder> <output_folder>"
    exit 1
fi

input_folder="$1"      # Set input folder path from first argument
output_folder="$2"     # Set output folder path from second argument

mkdir -p "$output_folder"  # Create output folder if it doesn't exist

for der_file in "$input_folder"/*.der; do
    if [ -f "$der_file" ]; then
        der_filename=$(basename "$der_file")
        pem_filename="${der_filename%.*}.pem"
        pem_output_path="$output_folder/$pem_filename"

        # Convert the certificate and capture errors
        if ! output=$(openssl x509 -inform DER -outform PEM -in "$der_file" -out "$pem_output_path" 2>&1); then
            # Extract relevant error message
            error_message=$(echo "$output" | grep -i 'unable to load certificate\|could not read certificate' | tail -n 1)
            echo "$der_filename Error: $error_message"
        else
            echo "$der_filename Converted"
        fi
    fi
done
