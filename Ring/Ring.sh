#!/bin/bash

mkdir -p ./result/half_duplex
mkdir -p ./intermediate

tools=(OpenSSL GnuTLS wolfSSL Cryptography Golang Bouncycastle)
input_dir=" "

if [ ! -d "$input_dir" ]; then
    echo "Error: Input directory $input_dir does not exist!"
    exit 1
fi

cp -r "$input_dir" "./intermediate/half_duplex_round0"

num_tools=${#tools[@]}

# Bouncycastle JAR Path
BCLIB="./program/lib/bcprov-jdk15on-1.70.jar:./program/lib/bcpkix-jdk15on-1.70.jar"

for ((i = 0; i < num_tools; i++)); do
    round_input="./intermediate/half_duplex_round$i"
    round_middle="./intermediate/half_duplex_round${i}_DER"
    round_output="./intermediate/half_duplex_round$((i+1))"
    mkdir -p "$round_middle"
    mkdir -p "$round_output"

    # PEM -> DER
    toolA="${tools[$i]}"
    execA="./program/${toolA}PtoD"
    logA="./result/half_duplex/${toolA}_PtoD.txt"

    echo "[$toolA PtoD] $round_input -> $round_middle"
    if [[ "$toolA" == "Cryptography" ]]; then
        python3 "${execA}.py" "$round_input" "$round_middle" >> "$logA" 2>&1
    elif [[ "$toolA" == "Bouncycastle" ]]; then
        java -cp "program:$BCLIB" BouncycastlePtoD "$round_input" "$round_middle" > "$logA" 2>&1
    elif [[ "$toolA" == "Golang" ]]; then
        go run "${execA}.go" -input "$round_input" -output "$round_middle" >> "$logA" 2>&1
    elif [[ "$toolA" == "OpenSSL" ]]; then
        sh "${execA}.sh" "$round_input" "$round_middle" >> "$logA" 2>&1
    else
        "$execA" "$round_input" "$round_middle" >> "$logA" 2>&1
    fi

    # DER -> PEM
    toolB="${tools[$(( (i+1) % num_tools ))]}"
    execB="./program/${toolB}DtoP"
    logB="./result/half_duplex/${toolB}_DtoP.txt"

    echo "[$toolB DtoP] $round_middle -> $round_output"
    if [[ "$toolB" == "Cryptography" ]]; then
        python3 "${execB}.py" "$round_middle" "$round_output" >> "$logB" 2>&1
    elif [[ "$toolB" == "Bouncycastle" ]]; then
        java -cp "program:$BCLIB" BouncycastleDtoP "$round_middle" "$round_output" > "$logB" 2>&1
    elif [[ "$toolB" == "Golang" ]]; then
        go run "${execB}.go" -input "$round_middle" -output "$round_output" >> "$logB" 2>&1
    elif [[ "$toolB" == "OpenSSL" ]]; then
        sh "${execB}.sh" "$round_middle" "$round_output" >> "$logB" 2>&1
    else
        "$execB" "$round_middle" "$round_output" >> "$logB" 2>&1
    fi
done

echo "Half-duplex ring conversion completed."

