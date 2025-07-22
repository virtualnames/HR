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
    derFolder := flag.String("input", "./der", "Directory containing DER certificates")
    pemFolder := flag.String("output", "./pem_c", "Directory to output PEM certificates")
    flag.Parse()

    if err := os.MkdirAll(*pemFolder, os.ModePerm); err != nil {
        fmt.Fprintf(os.Stderr, "Error: output directory creation %s\n", err)
        os.Exit(1)
    }

    files, err := os.ReadDir(*derFolder)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: reading input directory %s\n", err)
        os.Exit(1)
    }

    for _, f := range files {
        derPath := filepath.Join(*derFolder, f.Name())
        derBytes, err := os.ReadFile(derPath)
        if err != nil {
            fmt.Fprintf(os.Stderr, "%s Error: reading %s\n", f.Name(), err)
            continue
        }

        cert, err := x509.ParseCertificate(derBytes)
        if err != nil {
            fmt.Fprintf(os.Stderr, "%s Error: parsing %s\n", f.Name(), err)
            continue
        }

        pemBytes := pem.EncodeToMemory(&pem.Block{
            Type:  "CERTIFICATE",
            Bytes: cert.Raw,
        })

        derFileName := f.Name()
        derName := strings.TrimSuffix(derFileName, ".der")
        pemName := derName + ".pem"
        pemPath := filepath.Join(*pemFolder, pemName)

        err = os.WriteFile(pemPath, pemBytes, 0600)
        if err != nil {
            fmt.Fprintf(os.Stderr, "%s Error: writing %s\n", pemName, err)
            continue
        }

        fmt.Printf("%s Converted\n", derFileName)
    }
}
