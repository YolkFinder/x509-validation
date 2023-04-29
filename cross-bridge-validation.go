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

    // Verify cross-certificates in the AIA extension
    crossCerts := eeCert.AuthorityInfoAccess

    for _, crossCert := range crossCerts {
        if crossCert.Method != x509.OIDCAIssuer {
            continue
        }

        crossPEM, err := http.Get(crossCert.URI)
        if err != nil {
            fmt.Printf("Could not download cross-certificate from %s: %v\n", crossCert.URI, err)
            continue
        }

        crossCert, err := x509.ParseCertificate(crossPEM.Body)
        if err != nil {
            fmt.Printf("Could not parse cross-certificate from %s: %v\n", crossCert.URI, err)
            continue
        }

        _, err = crossCert.Verify(opts)
        if err != nil {
            fmt.Printf("Cross-certificate from %s is not valid: %v\n", crossCert.URI, err)
            continue
        }

        // Check for cross-certificate revocation
        for _, crlURL := range crossCert.CRLDistributionPoints {
            crlPEM, err := http.Get(crlURL)
            if err != nil {
                fmt.Printf("Could not download CRL for cross-certificate from %s: %v\n", crossCert.URI, err)
                continue
            }

            crlList, err := x509.ParseCRLsPEM(crlPEM.Body)
           
        if err != nil {
            fmt.Printf("Could not parse CRL for cross-certificate from %s: %v\n", crossCert.URI, err)
            continue
        }

        for _, crl := range crlList {
            if crl.HasExpiredAt(opts.CurrentTime) {
                fmt.Printf("CRL for cross-certificate from %s has expired\n", crossCert.URI)
                continue
            }

            if crl.IsRevoked(crossCert) {
                fmt.Printf("Cross-certificate from %s is revoked in CRL %v\n", crossCert.URI, crl.TBSCertList.RevokedCertificates)
                continue
            }
        }
    }

    // Check for cross-certificate expiration
    if crossCert.NotAfter.Before(opts.CurrentTime) {
        fmt.Printf("Cross-certificate from %s has expired\n", crossCert.URI)
        continue
    }

    fmt.Printf("Cross-certificate from %s is valid\n", crossCert.URI)
}
}
