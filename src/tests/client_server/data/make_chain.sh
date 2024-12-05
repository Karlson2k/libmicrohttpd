#! /bin/sh

echo "Combining ceritificates into the chain, excluding the root CA"
cat test-server.crt inter2-ca.crt inter1-ca.crt > chain.crt || \
  exit $?
echo "Created chain.crt"

# Verify result with GnuTLS's certtool (if available)
if command -v 'certtool' >/dev/null 2>&1; then
  echo "Checking chain.crt against the root CA"
  certtool --load-ca-certificate root-ca.crt --verify --verify-profile=high -d2 --infile chain.crt || \
    exit $?
else
  true
fi

echo "SUCCESS"
