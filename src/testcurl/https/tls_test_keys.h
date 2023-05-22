/*
     This file is part of libmicrohttpd
     Copyright (C) 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef MHD_TLS_TEST_KEYS_H
#define MHD_TLS_TEST_KEYS_H

/* Test Certificates */

/* Certificate Authority cert */
const char *const ca_cert_pem =
  "-----BEGIN CERTIFICATE-----\n\
MIIGITCCBAmgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCUlUx\n\
DzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwGTW9zY293MRswGQYDVQQKDBJ0ZXN0\n\
LWxpYm1pY3JvaHR0cGQxITAfBgkqhkiG9w0BCQEWEm5vYm9keUBleGFtcGxlLm9y\n\
ZzEQMA4GA1UEAwwHdGVzdC1DQTAgFw0yMTA0MDcxNzM2MThaGA8yMTIxMDMxNDE3\n\
MzYxOFowgYExCzAJBgNVBAYTAlJVMQ8wDQYDVQQIDAZNb3Njb3cxDzANBgNVBAcM\n\
Bk1vc2NvdzEbMBkGA1UECgwSdGVzdC1saWJtaWNyb2h0dHBkMSEwHwYJKoZIhvcN\n\
AQkBFhJub2JvZHlAZXhhbXBsZS5vcmcxEDAOBgNVBAMMB3Rlc3QtQ0EwggIiMA0G\n\
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDdaWupA4qZjCBNkJoJOm5xnCaizl36\n\
ZLUwp4xBL/YfXPWE3LkmAREiVI/YnAb8l6G7CJnz8dTsOJWkNXG6T1KVP5/2RvBI\n\
IaaaufRIAl7hEnj1j9E2hQlV2fxF2ZNhz+nqi0LqKV4LJSpclkXADf2FA9HsVRP/\n\
B7zYh+DP0fSU8V6bsu8XCeRGshroAPrc8rH8lFEEXpNLNIqQr8yKx6SmdB6hfja6\n\
6SQ0++qBhl0aJtn4LHWZohgjBmkIaGFPYIJLgxQ/xyp2Grz2q7lGKJ+zBkBF8iOP\n\
t3x+F1hSCBnr/DGYWmjEm5tYm+7pyuriPddXdCc8+qa2LxMZo3EXxLo5YISpPCyw\n\
Z7V3YAOZTr3m1C24LiYvPehCq1CTIkhhmqtlVJXU7ISD48cx9y+5Pi34wtbTI/gN\n\
x4voyTLAfyavKMmIpxxIRsWldiF2n06HdvCRVdihDQUad10ygTmWf1J/s2ZETAtH\n\
QaSd7MD389t6nQFtTIXigsNKnnDPlrtxt7rOLvLQeR0K04Gzrf/scheOanRAfOXH\n\
KNBFU7YkDFG8rqizlC65rx9qeXFYXQcHZTuqxK7tgZnSgJat3E70VbTSCsEEG7eR\n\
bNX/fChUKAIIpWaiW6HDlKLl6m2y+BzM91umBsKOqTvntMVFBSF9pVYlXK854aIR\n\
q8A2Xujd012seQIDAQABo4GfMIGcMAsGA1UdDwQEAwICpDASBgNVHRMBAf8ECDAG\n\
AQH/AgEBMB0GA1UdDgQWBBRYdUPApWoxw4U13Rqsjf9AHdbpLDATBgNVHSUEDDAK\n\
BggrBgEFBQcDATAkBglghkgBhvhCAQ0EFxYVVGVzdCBsaWJtaWNyb2h0dHBkIENB\n\
MB8GA1UdIwQYMBaAFFh1Q8ClajHDhTXdGqyN/0Ad1uksMA0GCSqGSIb3DQEBCwUA\n\
A4ICAQBvrrcTKVeI1EYnXo4BQD4oCvf9z1fYQmL21EbHwgjg1nmaPkvStgWAc5p1\n\
kKwySrpEMKXfu68X76RccXZyWWIamEjz2OCWYZgjX6d6FpjhLphL8WxXDy5C9eay\n\
ixN7+URz2XQoi22wqR+tCPDhrIzcMPyMkx/6gRgcYeDnaFrkdSeSsKsID4plfcIj\n\
ISWJDvv+IAgrtsG1NVHnGwpAv0od3A8/4/fR6PPyewaU3aydvjZ7Au8O9DGDjlU9\n\
9HdlOkkY6GVJ1pfGZib7cV7lhy0D2kj1g9xZh97YjpoUfppPl9r+6A8gDm0hXlAD\n\
TlzNYlwTb681ZEoSd9PiLEY8HETssHlays2dYXdcNwAEp69iIHz8q1Q98Be9LScl\n\
WEzgaOT9U7lpIw/MWbELoMsC+Ecs1cVWBIuiIq8aSG2kRr1x3S8yVXbAohAXif2s\n\
E6puieM/VJ25iaNhkbLmDkk58QVVmn9NZNv6ETxuSQMp9e0EwbVlj68vzClQ91Y/\n\
nmAiGcLFUEwB9G0szv9+vR+oDW4IkvdFZSUbcICd2cnynnwAD395onqS4hEZO1xM\n\
Gy5ZldbTMTjgn7fChNopz15ChPBnwFIjhm+S0CyiLRQAowfknRVq2IBkj7/5kOWg\n\
4mcxcq76HoQWK/8X/8RFL1eFVAvY7TNHYJ0RS51DMuwCNQictA==\n\
-----END CERTIFICATE-----";


/* test server key */
const char *const srv_signed_key_pem =
  "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCff7amw9zNSE+h\n\
rOMhBrzbbsJluUP3gmd8nOKY5MUimoPkxmAXfp2L0il+MPZT/ZEmo11q0k6J2jfG\n\
UBQ+oZW9ahNZ9gCDjbYlBblo/mqTai+LdeLO3qk53d0zrZKXvCO6sA3uKpG2WR+g\n\
+sNKxfYpIHCpanqBU6O+degIV/+WKy3nQ2Fwp7K5HUNj1u0pg0QQ18yf68LTnKFU\n\
HFjZmmaaopWki5wKSBieHivzQy6w+04HSTogHHRK/y/UcoJNSG7xnHmoPPo1vLT8\n\
CMRIYnSSgU3wJ43XBJ80WxrC2dcoZjV2XZz+XdQwCD4ZrC1ihykcAmiQA+sauNm7\n\
dztOMkGzAgMBAAECggEAIbKDzlvXDG/YkxnJqrKXt+yAmak4mNQuNP+YSCEdHSBz\n\
+SOILa6MbnvqVETX5grOXdFp7SWdfjZiTj2g6VKOJkSA7iKxHRoVf2DkOTB3J8np\n\
XZd8YaRdMGKVV1O2guQ20Dxd1RGdU18k9YfFNsj4Jtw5sTFTzHr1P0n9ybV9xCXp\n\
znSxVfRg8U6TcMHoRDJR9EMKQMO4W3OQEmreEPoGt2/+kMuiHjclxLtbwDxKXTLP\n\
pD0gdg3ibvlufk/ccKl/yAglDmd0dfW22oS7NgvRKUve7tzDxY1Q6O5v8BCnLFSW\n\
D+z4hS1PzooYRXRkM0xYudvPkryPyu+1kEpw3fNsoQKBgQDRfXJo82XQvlX8WPdZ\n\
Ts3PfBKKMVu3Wf8J3SYpuvYT816qR3ot6e4Ivv5ZCQkdDwzzBKe2jAv6JddMJIhx\n\
pkGHc0KKOodd9HoBewOd8Td++hapJAGaGblhL5beIidLKjXDjLqtgoHRGlv5Cojo\n\
zHa7Viel1eOPPcBumhp83oJ+mQKBgQDC6PmdETZdrW3QPm7ZXxRzF1vvpC55wmPg\n\
pRfTRM059jzRzAk0QiBgVp3yk2a6Ob3mB2MLfQVDgzGf37h2oO07s5nspSFZTFnM\n\
KgSjFy0xVOAVDLe+0VpbmLp1YUTYvdCNowaoTE7++5rpePUDu3BjAifx07/yaSB+\n\
W+YPOfOuKwKBgQCGK6g5G5qcJSuBIaHZ6yTZvIdLRu2M8vDral5k3793a6m3uWvB\n\
OFAh/eF9ONJDcD5E7zhTLEMHhXDs7YEN+QODMwjs6yuDu27gv97DK5j1lEsrLUpx\n\
XgRjAE3KG2m7NF+WzO1K74khWZaKXHrvTvTEaxudlO3X8h7rN3u7ee9uEQKBgQC2\n\
wI1zeTUZhsiFTlTPWfgppchdHPs6zUqq0wFQ5Zzr8Pa72+zxY+NJkU2NqinTCNsG\n\
ePykQ/gQgk2gUrt595AYv2De40IuoYk9BlTMuql0LNniwsbykwd/BOgnsSlFdEy8\n\
0RQn70zOhgmNSg2qDzDklJvxghLi7zE5aV9//V1/ewKBgFRHHZN1a8q/v8AAOeoB\n\
ROuXfgDDpxNNUKbzLL5MO5odgZGi61PBZlxffrSOqyZoJkzawXycNtoBP47tcVzT\n\
QPq5ZOB3kjHTcN7dRLmPWjji9h4O3eHCX67XaPVMSWiMuNtOZIg2an06+jxGFhLE\n\
qdJNJ1DkyUc9dN2cliX4R+rG\n\
-----END PRIVATE KEY-----";

/* test server CA signed certificates */
const char *const srv_signed_cert_pem =
  "-----BEGIN CERTIFICATE-----\n\
MIIFSzCCAzOgAwIBAgIBBDANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCUlUx\n\
DzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwGTW9zY293MRswGQYDVQQKDBJ0ZXN0\n\
LWxpYm1pY3JvaHR0cGQxITAfBgkqhkiG9w0BCQEWEm5vYm9keUBleGFtcGxlLm9y\n\
ZzEQMA4GA1UEAwwHdGVzdC1DQTAgFw0yMjA0MjAxODQzMDJaGA8yMTIyMDMyNjE4\n\
NDMwMlowZTELMAkGA1UEBhMCUlUxDzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwG\n\
TW9zY293MRswGQYDVQQKDBJ0ZXN0LWxpYm1pY3JvaHR0cGQxFzAVBgNVBAMMDnRl\n\
c3QtbWhkc2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn3+2\n\
psPczUhPoazjIQa8227CZblD94JnfJzimOTFIpqD5MZgF36di9IpfjD2U/2RJqNd\n\
atJOido3xlAUPqGVvWoTWfYAg422JQW5aP5qk2ovi3Xizt6pOd3dM62Sl7wjurAN\n\
7iqRtlkfoPrDSsX2KSBwqWp6gVOjvnXoCFf/list50NhcKeyuR1DY9btKYNEENfM\n\
n+vC05yhVBxY2ZpmmqKVpIucCkgYnh4r80MusPtOB0k6IBx0Sv8v1HKCTUhu8Zx5\n\
qDz6Nby0/AjESGJ0koFN8CeN1wSfNFsawtnXKGY1dl2c/l3UMAg+GawtYocpHAJo\n\
kAPrGrjZu3c7TjJBswIDAQABo4HmMIHjMAsGA1UdDwQEAwIFoDAMBgNVHRMBAf8E\n\
AjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMBMDEGA1UdEQQqMCiCDnRlc3QtbWhk\n\
c2VydmVyhwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMB0GA1UdDgQWBBQ57Z06WJae\n\
8fJIHId4QGx/HsRgDDAoBglghkgBhvhCAQ0EGxYZVGVzdCBsaWJtaWNyb2h0dHBk\n\
IHNlcnZlcjARBglghkgBhvhCAQEEBAMCBkAwHwYDVR0jBBgwFoAUWHVDwKVqMcOF\n\
Nd0arI3/QB3W6SwwDQYJKoZIhvcNAQELBQADggIBAI7Lggm/XzpugV93H5+KV48x\n\
X+Ct8unNmPCSzCaI5hAHGeBBJpvD0KME5oiJ5p2wfCtK5Dt9zzf0S0xYdRKqU8+N\n\
aKIvPoU1hFixXLwTte1qOp6TviGvA9Xn2Fc4n36dLt6e9aiqDnqPbJgBwcVO82ll\n\
HJxVr3WbrAcQTB3irFUMqgAke/Cva9Bw79VZgX4ghb5EnejDzuyup4pHGzV10Myv\n\
hdg+VWZbAxpCe0S4eKmstZC7mWsFCLeoRTf/9Pk1kQ6+azbTuV/9QOBNfFi8QNyb\n\
18jUjmm8sc2HKo8miCGqb2sFqaGD918hfkWmR+fFkzQ3DZQrT+eYbKq2un3k0pMy\n\
UySy8SRn1eadfab+GwBVb68I9TrPRMrJsIzysNXMX4iKYl2fFE/RSNnaHtPw0C8y\n\
B7memyxPRl+H2xg6UjpoKYh3+8e44/XKm0rNIzXjrwA8f8gnw2TbqmMDkj1YqGnC\n\
SCj5A27zUzaf2pT/YsnQXIWOJjVvbEI+YKj34wKWyTrXA093y8YI8T3mal7Kr9YM\n\
WiIyPts0/aVeziM0Gunglz+8Rj1VesL52FTurobqusPgM/AME82+qb/qnxuPaCKj\n\
OT1qAbIblaRuWqCsid8BzP7ZQiAnAWgMRSUg1gzDwSwRhrYQRRWAyn/Qipzec+27\n\
/w0gW9EVWzFhsFeGEssi\n\
-----END CERTIFICATE-----";

/* test server self signed certificates */
const char *const srv_self_signed_cert_pem = \
  "-----BEGIN CERTIFICATE-----\n"
  "MIIC+jCCAeSgAwIBAgIES0KCvTALBgkqhkiG9w0BAQUwFzEVMBMGA1UEAxMMdGVz\n"
  "dF9jYV9jZXJ0MB4XDTEwMDEwNTAwMDcyNVoXDTQ1MDMxMjAwMDcyNVowFzEVMBMG\n"
  "A1UEAxMMdGVzdF9jYV9jZXJ0MIIBHzALBgkqhkiG9w0BAQEDggEOADCCAQkCggEA\n"
  "tDEagv3p9OUhUL55jMucxjNK9N5cuozhcnrwDfBSU6oVrqm5kPqO1I7Cggzw68Y5\n"
  "jhTcBi4FXmYOZppm1R3MhSJ5JSi/67Q7X4J5rnJLXYGN27qjMpnoGQ/2xmsNG/is\n"
  "i+h/2vbtPU+WP9SEJnTfPLLpZ7KqCAk7FUUzKsuLx3/SOKtdkrWxPKwYTgnDEN6D\n"
  "JL7tEzCnG5DFc4mQ7YW9PaRdC3rS1T8PvQ3jB2BUnohM0cFvKRuiU35tU7h7CPbL\n"
  "4L66VglXoiwqmgcrwI2U968bD0+wRQ5c5bzNoshJOzN6CTMh1IhbklSh/Z6FA/e8\n"
  "hj0yVo2tdllXuJGVs3PIEwIDAQABo1UwUzAMBgNVHRMBAf8EAjAAMBMGA1UdJQQM\n"
  "MAoGCCsGAQUFBwMBMA8GA1UdDwEB/wQFAwMHIAAwHQYDVR0OBBYEFDfU7pAv9LYn\n"
  "n7jb4WHl4+Vgi2FnMAsGCSqGSIb3DQEBBQOCAQEAkaembPQMmv6OOjbIod8zTatr\n"
  "x5Bwkwp3TOE1NRyy2OytzFIYRUkNrZYlcmrxcbNNycIK41CNVXbriFCF8gcmIq9y\n"
  "vaKZn8Gcy+vGggv+1BP9IAPBGKRwSi0wmq9JoGE8hx+qqTpRSdfbM/cps/09hicO\n"
  "0EIR7kWEbvnpMBcMKYOtYE9Gce7rdSMWVAsKc174xn8vW6TxCUvmWFv5DPg5HG1v\n"
  "y1SUX73qafRo+W6FN4UC/DHfwRhF8RSKEnVbmgDVCs6GHdKBjU2qRgYyj6nWZqK1\n"
  "XFUTWgia+Fl3D9vlsXaFcSZKA0Bq1eojl0B0AfeYAxTFwPWXscKvt/bXZfH8bg==\n"
  "-----END CERTIFICATE-----\n";

/* test server key */
const char *const srv_key_pem = \
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEpAIBAAKCAQEAtDEagv3p9OUhUL55jMucxjNK9N5cuozhcnrwDfBSU6oVrqm5\n"
  "kPqO1I7Cggzw68Y5jhTcBi4FXmYOZppm1R3MhSJ5JSi/67Q7X4J5rnJLXYGN27qj\n"
  "MpnoGQ/2xmsNG/isi+h/2vbtPU+WP9SEJnTfPLLpZ7KqCAk7FUUzKsuLx3/SOKtd\n"
  "krWxPKwYTgnDEN6DJL7tEzCnG5DFc4mQ7YW9PaRdC3rS1T8PvQ3jB2BUnohM0cFv\n"
  "KRuiU35tU7h7CPbL4L66VglXoiwqmgcrwI2U968bD0+wRQ5c5bzNoshJOzN6CTMh\n"
  "1IhbklSh/Z6FA/e8hj0yVo2tdllXuJGVs3PIEwIDAQABAoIBAAEtcg+LFLGtoxjq\n"
  "b+tFttBJfbRcfdG6ocYqBGmUXF+MgFs573DHX3sHNOQxlaNHtSgIclF1eYgNZFFt\n"
  "VLIoBFTzfEQXoFosPUDoEuqVMeXLttmD7P2jwL780XJLZ4Xj6GY07npq1iGBcEZf\n"
  "yCcdoyGkr9jgc5Auyis8DStGg/jfUBC4NBvF0GnuuNPAdYRPKUpKw9EatI+FdMjy\n"
  "BuroD90fhdkK8EwMEVb9P17bdIc1MCIZFpUE9YHjVdK/oxCUhQ8KRfdbI4JU5Zh3\n"
  "UtO6Jm2wFuP3VmeVpPvE/C2rxI70pyl6HMSiFGNc0rhJYCQ+yhohWj7nZ67H4vLx\n"
  "plv5LxkCgYEAz7ewou8oFafDAMNoxaqKudvUg+lxXewdLDKaYBF5ACi9uAPCJ+v7\n"
  "M5c/fvPFn/XHzo7xaXbtTAH3Z5xzBs+80OsvL+e1Ut4xR+ELRkybknh/s2wQeABk\n"
  "Kb0vA59ukQGj12LV5phZMaVoXe6KJ7hZnN62d3K6m1wGE/k58i4pPLUCgYEA3hN8\n"
  "G95zW7g0jVdSr+KUeVmephph9yh8Yb+3I3ojwOIv6d45TopGx8pFZlnBAMZf1ZQx\n"
  "DIhzJNnaqZy/4w7RNaOGWnPA/5f+MIoHBiLGEEmfHC3lt087Yp9OuwDUHwpETYdV\n"
  "o+KBCvVh60Et3bZUgF/1k/3YXxn8J5dsmJsjNqcCgYBLflyRa1BrRnTGMz9CEDCp\n"
  "Si9b3h1Y4Hbd2GppHhCXMTd6yMrpDYhYANGQB3M9Juv+s88j4JhwNoq/uonH4Pqk\n"
  "B8Y3qAQr4RuSH0WkwDUOsALhqBX4N1QwI1USAQEDbNAqeP5698X7GD3tXcQSmZrg\n"
  "O8WfdjBCRNjkq4EW9xX/vQKBgQDONtmwJ0iHiu2BseyeVo/4fzfKlgUSNQ4K1rOA\n"
  "xhIdMeu8Bxa/z7caHsGC4SVPSuYCtbE2Kh6BwapChcPJXCD45fgEViiJLuJiwEj1\n"
  "caTpyvNsf1IoffJvCe9ZxtMyX549P8ZOgC3Dt0hN5CBrGLwu2Ox5l+YrqT10pi+5\n"
  "JZX1UQKBgQCrcXrdkkDAc/a4+PxNRpJRLcU4fhv8/lr+UWItE8eUe7bd25bTQfQm\n"
  "VpNKc/kAJ66PjIED6fy3ADhd2y4naT2a24uAgQ/M494J68qLnGh6K4JU/09uxR2v\n"
  "1i2q/4FNLdFFk1XP4iNnTHRLZ+NYr2p5Y9RcvQfTjOauz8Ahav0lyg==\n"
  "-----END RSA PRIVATE KEY-----\n";

#endif
