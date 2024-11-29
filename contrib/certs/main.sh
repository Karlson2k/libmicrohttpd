#!/bin/bash
# This file is in the public domain.

set -xeu

# create root CA certificate and key.
openssl req -x509 \
        -out rca-signed-cert.pem \
        -outform PEM \
        -extensions v3_ca \
        -days 3650 \
        -subj "/C=US/ST=Massachusetts/L=Boston/O=Root/CN=ca.gnu" \
        -passout 'pass:masterword'
# private key was written to privkey.pem
mv privkey.pem rca-private-key.pem

# We can skip these with contemporary OpenSSL:
# convert to certificate request:
#openssl x509 -x509toreq \
#        -in rca-unsigned-cert.pem \
#        -out rca-csr.pem \
#        -passin 'pass:masterword' \
#        -signkey rca-private-key.pem

# self-sign using:
#openssl x509 -req \
#        -in rca-csr.pem \
#        -extfile openssl.cnf \
#        -extensions v3_ca \
#        -signkey rca-private-key.pem \
#        -passin 'pass:masterword' \
#        -out rca-signed-cert.pem

#rm rca-csr.pem rca-unsigned-cert.pem

# view using:
# openssl x509 -in rca-signed-cert.pem -text -noout

# Setup CA directory structure
rm -rf dir/
mkdir -p dir certdir
echo 1000 > dir/serial.txt
touch dir/index.txt dir/index.txt.attr


# create client of root CA private key
openssl genpkey \
        -algorithm RSA \
        -pass 'pass:clientword' \
        -out client-of-rca-private-key.pem \
        -aes-128-cbc \
        -pkeyopt \
        rsa_keygen_bits:2048
# create CSR
openssl req -new \
        -key client-of-rca-private-key.pem \
        -keyform PEM \
        -passin 'pass:clientword' \
        -subj "/C=US/ST=Massachusetts/L=Boston/O=Client/CN=client.ca.gnu" \
        -out client-of-rca-csr.pem \
        -outform PEM

# Sign CSR as CA
openssl ca \
        -in client-of-rca-csr.pem \
        -batch \
        -out client-of-rca-signed-cert.pem \
        -passin 'pass:masterword' \
        -config ca.conf


rm client-of-rca-csr.pem

# Setup ICA directory structure
rm -rf idir
mkdir -p idir icertdir
echo 1000 > idir/serial.txt
touch idir/index.txt idir/index.txt.attr


# create ICA private key
openssl genpkey \
        -algorithm RSA \
        -pass 'pass:icaword' \
        -out ica-private-key.pem \
        -aes-128-cbc \
        -pkeyopt \
        rsa_keygen_bits:2048
# create CSR
openssl req -new \
        -key ica-private-key.pem \
        -keyform PEM \
        -passin 'pass:icaword' \
        -subj "/C=US/ST=Massachusetts/L=Boston/O=ICA/CN=ica.gnu" \
        -out ica-csr.pem \
        -outform PEM

# Sign CSR as CA
openssl ca \
        -in ica-csr.pem \
        -batch \
        -extensions v3_intermediate_ca \
        -out ica-signed-cert.pem \
        -passin 'pass:masterword' \
        -config ca.conf \
        -outform PEM

rm ica-csr.pem

# view using:
# openssl x509 -in ica-signed-cert.pem -text -noout

# Create certificate chain
cat ica-signed-cert.pem rca-signed-cert.pem > ica-chain.pem


# create ICA client private key
openssl genpkey \
        -algorithm RSA \
        -pass 'pass:iclientword' \
        -out client-of-ica-private-key.pem \
        -aes-128-cbc \
        -pkeyopt \
        rsa_keygen_bits:2048
# create CSR
openssl req -new \
        -key client-of-ica-private-key.pem \
        -keyform PEM \
        -passin 'pass:iclientword' \
        -subj "/C=US/ST=Massachusetts/L=Boston/O=ICA-Client/CN=client.ica.gnu" \
        -out client-of-ica-csr.pem \
        -outform PEM

# Sign CSR as CA
openssl ca \
        -in client-of-ica-csr.pem \
        -batch \
        -section ICA_default \
        -out client-of-ica-signed-cert.pem \
        -passin 'pass:icaword' \
        -config ca.conf \
        -outform PEM

rm client-of-ica-csr.pem

cat rca-signed-cert.pem ica-signed-cert.pem client-of-ica-signed-cert.pem > client-of-ica-chain.pem

# Check result
openssl verify -verbose -CAfile rca-signed-cert.pem client-of-ica-chain.pem

# create 2nd ICA client private key
openssl genpkey \
        -algorithm RSA \
        -pass 'pass:iclientword' \
        -out client2-of-ica-private-key.pem \
        -aes-128-cbc \
        -pkeyopt \
        rsa_keygen_bits:2048
# create CSR
openssl req -new \
        -key client2-of-ica-private-key.pem \
        -keyform PEM \
        -passin 'pass:iclientword' \
        -subj "/C=US/ST=Massachusetts/L=Boston/O=ICA-Client/CN=other.ica.gnu" \
        -out client2-of-ica-csr.pem \
        -outform PEM

# Sign CSR as CA
openssl ca \
        -in client2-of-ica-csr.pem \
        -batch \
        -section ICA_default \
        -out client2-of-ica-signed-cert.pem \
        -passin 'pass:icaword' \
        -config ca.conf \
        -outform PEM

rm client2-of-ica-csr.pem

cat rca-signed-cert.pem ica-signed-cert.pem client2-of-ica-signed-cert.pem > client2-of-ica-chain.pem

# Check result
openssl verify -verbose -CAfile rca-signed-cert.pem client2-of-ica-chain.pem
