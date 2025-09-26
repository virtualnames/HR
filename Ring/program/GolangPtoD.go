package main

import (
    "crypto/x509"
    "encoding/pem"
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

func main() {
    pemFolder := flag.String("input", "./pem", "Directory containing PEM certificates")
    derFolder := flag.String("output", "./der_c", "Directory to output DER certificates")
    flag.Parse()

    if err := os.MkdirAll(*derFolder, os.ModePerm); err != nil {
        fmt.Fprintf(os.Stderr, "Error: creating output directory %s\n", err)
        os.Exit(1)
    }

    files, err := os.ReadDir(*pemFolder)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: reading input directory %s\n", err)
        os.Exit(1)
    }

    for _, f := range files {
        pemPath := filepath.Join(*pemFolder, f.Name())
        pemBytes, err := os.ReadFile(pemPath)
        if err != nil {
            fmt.Fprintf(os.Stderr, "%s Error: reading %s\n", f.Name(), err)
            continue
        }

        block, _ := pem.Decode(pemBytes)
        if block == nil || block.Type != "CERTIFICATE" {
            fmt.Fprintf(os.Stderr, "%s Error: invalid PEM block or not a certificate\n", f.Name())
            continue
        }

        _, err = x509.ParseCertificate(block.Bytes)
        if err != nil {
            fmt.Fprintf(os.Stderr, "%s Error: parsing certificate %s\n", f.Name(), err)
            continue
        }

        derName := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name())) + ".der"
        derPath := filepath.Join(*derFolder, derName)

        err = os.WriteFile(derPath, block.Bytes, 0600)
        if err != nil {
            fmt.Fprintf(os.Stderr, "%s Error: writing DER file %s\n", derName, err)
            continue
        }

        fmt.Printf("%s Converted\n", f.Name())
    }
}

