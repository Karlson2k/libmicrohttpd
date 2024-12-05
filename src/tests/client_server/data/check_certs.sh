#! /bin/sh

openssl x509 -in root-ca.crt -text -noout || \
  exit $?

openssl x509 -in inter1-ca.crt -text -noout || \
  exit $?

openssl x509 -in inter2-ca.crt -text -noout || \
  exit $?

openssl x509 -in test-server.crt -text -noout || \
  exit $?

echo "Checking server sertificate, with checking CAs up to the root CA..."
openssl verify -verbose -x509_strict -auth_level 3 \
  -no-CAfile -no-CApath -no-CAstore \
  -untrusted inter1-ca.crt \
  -untrusted inter2-ca.crt \
  -CAfile root-ca.crt \
  test-server.crt || \
  exit $?


echo "SUCCEED"
