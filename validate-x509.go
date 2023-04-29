package main

import (
    "crypto/x509"
    "fmt"
    "net/http"
    "time"
)

func main() {
    // Load the end-entity certificate to be verified
    eePEM, err := http.Get("https://example.com/certificate.pem")
    if err != nil {
        panic(err)
    }

    eeCert, err := x509.ParseCertificate(eePEM.Body)
    if err != nil {
        panic(err)
    }

    // Verify the certificate chain
    opts := x509.VerifyOptions{
        CurrentTime: time.Now(),
        DNSName:     "example.com",
    }

    _, err = eeCert.Verify(opts)
    if err != nil {
        panic(err)
    }

    // Check for certificate revocation
    crlSet := x509.NewCertPool()

    for _, crlURL := range eeCert.CRLDistributionPoints {
        crlPEM, err := http.Get(crlURL)
        if err != nil {
            panic(err)
        }

        crlList, err := x509.ParseCRLsPEM(crlPEM.Body)
        if err != nil {
            panic(err)
        }

        for _, crl := range crlList {
            crlSet.AddCert(crl)
        }
    }

    ocspServer := eeCert.OCSPServer[0]
    ocspPEM, err := http.Get(ocspServer)
    if err != nil {
        panic(err)
    }

    ocspResponse, err := http.Post(ocspServer, "application/ocsp-request", ocspPEM.Body)
    if err != nil {
        panic(err)
    }

    ocspParsedResponse, err := ocsp.ParseResponse(ocspResponse.Body)
    if err != nil {
        panic(err)
    }

    if ocspParsedResponse.Status == ocsp.Revoked {
        fmt.Println("The end-entity certificate is revoked")
    }

    // Check for revocation of intermediate and root certificates
    for _, cert := range eeCert.IntermediateCertificates {
        for _, crlURL := range cert.CRLDistributionPoints {
            crlPEM, err := http.Get(crlURL)
            if err != nil {
                panic(err)
            }

            crlList, err := x509.ParseCRLsPEM(crlPEM.Body)
            if err != nil {
                panic(err)
            }

            for _, crl := range crlList {
                crlSet.AddCert(crl)
            }
        }

        ocspServer := cert.OCSPServer[0]
        ocspPEM, err := http.Get(ocspServer)
        if err != nil {
            panic(err)
        }

        ocspResponse, err := http.Post(ocspServer, "application/ocsp-request", ocspPEM.Body)
        if err != nil {
            panic(err)
        }

        ocspParsedResponse, err := ocsp.ParseResponse(ocspResponse.Body)
        if err != nil {
            panic(err)
        }

        if ocspParsedResponse.Status == ocsp.Revoked {
            fmt.Println("A certificate in the chain is revoked")
        }
    }

    fmt.Println("Certificate chain verification complete")
}

