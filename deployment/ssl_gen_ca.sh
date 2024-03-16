#!/bin/bash

if [ ! -d "certs" ]; then
    mkdir "certs"
fi

# Clean up
rm -f certs/*.key
# rm -f certs/*.csr
rm -f certs/*.pem

# Generate root CA private key
openssl genpkey -algorithm ed25519 -out certs/rootCA.key
# openssl genpkey -algorithm ed25519 -out certs/ap.key
# openssl genpkey -algorithm ed25519 -out certs/cmp1.key
# openssl genpkey -algorithm ed25519 -out certs/cmp2.key

# Generate the root certificate (the host computer)
openssl req -x509 -new -nodes -config openssl_ca.conf -extensions ca_extensions -set_serial 20 -key certs/rootCA.key -days 1024 -out certs/rootCA.pem

# Generate certificate signing requests (CSRs) for all devices
# openssl req -new -config openssl.conf -key certs/ap.key -out certs/ap.csr
# openssl req -new -config openssl.conf -key certs/cmp1.key -out certs/cmp1.csr
# openssl req -new -config openssl.conf -key certs/cmp2.key -out certs/cmp2.csr

# Sign the CSR, creating a certificate
# openssl x509 -req -in certs/ap.csr -CA certs/rootCA.pem -CAkey certs/rootCA.key -extfile openssl.conf -extensions x509v3_extensions  -set_serial 21 -out certs/ap.crt -days 365 -sha256
# openssl x509 -req -in certs/cmp1.csr -CA certs/rootCA.pem -CAkey certs/rootCA.key -extfile openssl.conf -extensions x509v3_extensions  -set_serial 21 -out certs/cmp1.crt -days 365 -sha256
# openssl x509 -req -in certs/cmp2.csr -CA certs/rootCA.pem -CAkey certs/rootCA.key -extfile openssl.conf -extensions x509v3_extensions  -set_serial 21 -out certs/cmp2.crt -days 365 -sha256

# Verify the certificates
# openssl x509 -in ap.crt -text -noout
# openssl x509 -in cmp1.crt -text -noout
# openssl x509 -in cmp2.crt -text -noout
