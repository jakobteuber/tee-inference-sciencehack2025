#!/usr/bin/env bash
# Generate self-signed Server certificates


# Create Certification Authority
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem \
    -subj "/C=DE/ST=BY/L=Munich/O=RocketBoyz/CN=RocketBoyzCA"

# Create Server Key 
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=DE/ST=BY/L=Munich/O=RocketBoyz/CN=localhost"

# SAN extension file for server, so it is valid on `localhost`
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign Server Certificate 
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -out server-cert.pem -days 365 -sha256 -extfile server.ext

rm server.csr server.ext


