/*
     This file is part of libmicrohttpd
     (C) 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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

/* Certificate Authority key */
const char ca_key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEpAIBAAKCAQEA3vzPUd2yRjeHy9Yi22uX1vGnUPmB5zS+77/B9LubTqnNJ9eB\n"
  "jiMegQJsJWFQT/CW8FurYiSMXIuTBirZX7NO6/rlcqifdfKLotSUuXLu5DBvMLCv\n"
  "nQ73wCIdCJoVyJbRN0ExHsyGwCDCxaHuY8FlkIsfYo17SNmJNaMSUqdoAZoelmbq\n"
  "r9oVciRCQGgrmwEJdPj7EAofWSudV77y85j5rV/t51eNy5liS2qXnoFEmeqTuBo1\n"
  "1cSmRbv5dkCHbx+youLyZG39KxB0MZ124Na3qbUY41BPNj1XBljyAoHyY0J1iDqS\n"
  "0Zo+njEW6vRbmSMkrA1kH45+alN50X11mSgfoQIDAQABAoIBAAmLu+4Ushpdi5Sd\n"
  "P1cidjDFXfDaao5I2LTroghpnNyfaiT+zbj1jctu7K1luuX+Lh7+ZKIGH6RhVP8g\n"
  "R9eYBeyWHDsWJwPqCQJkrHR7LCkEfgkRAkaUZsSgzTqCWqUAeFa/xaQcdDcOu/nR\n"
  "DKMUexYmz4ZU+VJxPhWHzGuxhxM85uJOPK3rCaYCJoo1vMpF7MeFFvVljhSdyht5\n"
  "KD0w6qP0Y+vDe4cD/4W3wq82qXCFPA5oImjSJveEIJumPIjOyLFF+9p9V6hzg8Em\n"
  "48cpXcV3SsbaqTr6mSQl6b15zVwWq4CCt4mkeu6vK9PGzdnBiUmWaSXfprDwHaB3\n"
  "t1N0GRECgYEA5gP0gmZQDDJTlaGK9Z6pWiwpMBUoYcnqvCn8MQ5uPQn+KZir19AJ\n"
  "PkVLfWT9Dcaf3+2d0kBBgGYFWL+wK8DgrqALiLJfM6gP3Ts7G6Bis4GFdWY9aUnT\n"
  "6ZhRYdzetVArhTZBRKh8ERQNPy4TmzWDtjVUAfezUcvXqOjl9H5Q01ECgYEA+C2b\n"
  "i05t/RYcU0eFVYK8Yfl3jZJiopMdYwXCSCO21Ag2i0fjKC89rCmLlliffSSuDtNk\n"
  "xFsaSjns8Vyl7sjMcAOfsGokiUIcFnK/LyVoc3ie2NCiLVzw6zKK8lJ4bhn4afnv\n"
  "N9RKXP76emb8MaZroKlKkhMR8f2BvzXbv2NyU1ECgYEAtJeAXu1zhc/xnjaiQqxa\n"
  "rMilYfIKrZR571hLgDyjQttYqVIMAbp9t11yorYqlKlRFuCaG9yFUQlIw2BlMkUS\n"
  "YyiXRbE+W/Fk2z7I7qzjMarMnNsz9jmX3vzPULW4ScTzFnj9j6l1F3eV2vgTPrYq\n"
  "fmGqXo0bRmp0HVMWUPrn/LECgYEA3qHTQkHGS16VZGPpiY8xPVbUV8z07NC6cQVO\n"
  "hvZ64XTIsWN4tKjEU3glf2bbFCFef3BFmhv71pBmLRMmy7GYK/gkPdbKFdOXbM/d\n"
  "EAcnz0ZqgSeQBM+2U9dQbBdtb5+eiDsszNGFMC2QN1PBcyzOqh6UBbxTwdjfls9S\n"
  "5Trp6TECgYAzCZmmJuBW6WDK5ttOF/do6r0aurHr2mOr8oYxmBkhI3wphyUMNuaH\n"
  "rUk+R8LAmC1U4MbvvqoZH27xe+xd25mn6whitgZBH3DIetN7myDJep8wEG6aW4R5\n"
  "S82zk+LQJ7LTa1nPVPMS10qUXSH9cjShhszfeRIQM+lWbPoaEuo3yQ==\n"
  "-----END RSA PRIVATE KEY-----\n";

/* Certificate Authority cert */
const char ca_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIC6DCCAdKgAwIBAgIESHv2uDALBgkqhkiG9w0BAQUwFzEVMBMGA1UEAxMMdGVz\n"
  "dF9jYV9jZXJ0MB4XDTA4MDcxNTAxMDA0MFoXDTA5MDcxNTAxMDA0MFowFzEVMBMG\n"
  "A1UEAxMMdGVzdF9jYV9jZXJ0MIIBHzALBgkqhkiG9w0BAQEDggEOADCCAQkCggEA\n"
  "3vzPUd2yRjeHy9Yi22uX1vGnUPmB5zS+77/B9LubTqnNJ9eBjiMegQJsJWFQT/CW\n"
  "8FurYiSMXIuTBirZX7NO6/rlcqifdfKLotSUuXLu5DBvMLCvnQ73wCIdCJoVyJbR\n"
  "N0ExHsyGwCDCxaHuY8FlkIsfYo17SNmJNaMSUqdoAZoelmbqr9oVciRCQGgrmwEJ\n"
  "dPj7EAofWSudV77y85j5rV/t51eNy5liS2qXnoFEmeqTuBo11cSmRbv5dkCHbx+y\n"
  "ouLyZG39KxB0MZ124Na3qbUY41BPNj1XBljyAoHyY0J1iDqS0Zo+njEW6vRbmSMk\n"
  "rA1kH45+alN50X11mSgfoQIDAQABo0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud\n"
  "DwEB/wQFAwMHBAAwHQYDVR0OBBYEFB3x03+3Qa2SDwRF6RkNcjg9zRHJMAsGCSqG\n"
  "SIb3DQEBBQOCAQEAjPoKMve8aqtL8fFXfSkYwLJUwuTG4E4mX804O5dsdvOEWR2/\n"
  "UQm5IDiAZ3fnHE8zh0C1Kg+dWnCv0i1Q5CYZJ5sSY3tKikG5UBPVJGV1tT0vDfmJ\n"
  "X7b52y35eN8qe5DsdyDAcF2GNRBU8opkLkyXb8U095AQiCHzTPpiesZd5phJlMPm\n"
  "AJaB4VtHAykDMeKd7HJAeelRi/1dP8xsYNc1z67cSrkt2f+B0WAyuAUBBr1NdYmS\n"
  "duegptXCh8OeGEL/v6mbIWoszDbOjk/0zwsgW8BD/eXaZgPPEUtmHizYPIRPdeW1\n"
  "MSCwccjl/XjDkIoN8kKss4Ftt+Wyajjjxeh6YA==\n" "-----END CERTIFICATE-----\n";

/* test server CA signed certificates */
const char srv_signed_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDHzCCAgmgAwIBAgIESHv6kTALBgkqhkiG9w0BAQUwFzEVMBMGA1UEAxMMdGVz\n"
  "dF9jYV9jZXJ0MB4XDTA4MDcxNTAxMTcwNVoXDTA5MDcxNTAxMTcwNVowGzEZMBcG\n"
  "A1UEAxMQdGVzdF9zZXJ2ZXJfY2VydDCCAR8wCwYJKoZIhvcNAQEBA4IBDgAwggEJ\n"
  "AoIBAJIY2+Wn+TRHIJ92tpNvCIE6FOsGclRxOFJwK0T6k3SK68LwQ9PkQTTB/DJu\n"
  "+hU2u6w6lt1+Q8PHTDMLtnkEeXnxPn1uQZnnMEBcHAGY1U99iJh0At68AyoG7nkb\n"
  "AzgzxxjMom+dEhGEFHOg9JKmJp138RzIWcMN2l4pKIryiBUh5AWt/7uqtA+9fQMq\n"
  "nOeO8OU5FM3eKevl3VSZ6usptbePbUDNs5uEmG+PTR0bc2rYgGeC4+wExWcJ+CAq\n"
  "voNVPno//MoMeJjWgXqF4wTBFdfsewngkflwRDPuZuLsxVrKnIx6jsBKIMuhVuxT\n"
  "66vnEmuR34TUIzLlVPcJ5wmby2UCAwEAAaN2MHQwDAYDVR0TAQH/BAIwADATBgNV\n"
  "HSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDByAAMB0GA1UdDgQWBBSHX75y\n"
  "gpEjstognUu4If50qWXQaDAfBgNVHSMEGDAWgBQd8dN/t0Gtkg8ERekZDXI4Pc0R\n"
  "yTALBgkqhkiG9w0BAQUDggEBAF56YMCdp0C88ZF9yaXJZ4PMuTpW83Mhg5Ar0a9H\n"
  "DasF58p8eeRLhsTJPi+NpFSMTujEabGS3+8l6Iu5F5stFgvbvnjLHdYu2Pjakos8\n"
  "NjZCCkuEmIO4PLd6h5ToOZf3ZXNHmFjRTtKHQKNrYizlHlgnEDcUbU4gB5KOg3jU\n"
  "rv/Mtar+5LRK7KvByswp26nRH1ijGV23sy9StK7tV/cJPe/UkxyUfSQwUmQzzWe6\n"
  "QGAQtppUjGabWXjuLuOUyiG5LReYC5ri7XZuVekCAfUHbOdPYTHPczvpKBnUyKIv\n"
  "BRKOarmNfNc3w5G7Ast3jNOE2JfiJ8+x9+rMWI01PlWVYvQ=\n"
  "-----END CERTIFICATE-----\n";

/* test server key */
const char srv_signed_key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEpAIBAAKCAQEAkhjb5af5NEcgn3a2k28IgToU6wZyVHE4UnArRPqTdIrrwvBD\n"
  "0+RBNMH8Mm76FTa7rDqW3X5Dw8dMMwu2eQR5efE+fW5BmecwQFwcAZjVT32ImHQC\n"
  "3rwDKgbueRsDODPHGMyib50SEYQUc6D0kqYmnXfxHMhZww3aXikoivKIFSHkBa3/\n"
  "u6q0D719Ayqc547w5TkUzd4p6+XdVJnq6ym1t49tQM2zm4SYb49NHRtzatiAZ4Lj\n"
  "7ATFZwn4ICq+g1U+ej/8ygx4mNaBeoXjBMEV1+x7CeCR+XBEM+5m4uzFWsqcjHqO\n"
  "wEogy6FW7FPrq+cSa5HfhNQjMuVU9wnnCZvLZQIDAQABAoIBABISPh0FrocfZzMi\n"
  "YYoSGWi2sQCzTvAQAyn7UvbY0eWAC5KU2qb6nHA0sIfif0+hcgxnQOML68DrRYso\n"
  "3zzP52DEjPjB6x5o4OiNHC+8YmJPQlatPu+jLPcFXXkgdMD+cpmoMk2BDcuZ3VfC\n"
  "KI59O9iNjgcD50p/y6uLBsdNIbUPSMe8ONWT7f5DN/DqEL+3tVZaRAOL+C8iKYf4\n"
  "EPI5z6gOyL0aEpulbMKc0YoZZ2kDmu5IyMLgkF3DJV440Y/6IGan88ZSjk6i/d7f\n"
  "ciKVtzIIbr5ubbuGe3htphTpRP0aA5WuVTzHrKk83/u3hG1RFv1q/cRD28tVUIII\n"
  "0pcwLmECgYEAwMdaR5Y2NqBk/fOvU/oCDAQ6w8jmIa4zMxskvq9Pr753jhT13j+T\n"
  "eQ1A590PF4PPvGFTqJ2vl3kj6JT5dzu7mGKoJLFsnttpw+0NYUgp0waPPZx010pp\n"
  "QGeyQ/cPsZEZkCehh9c5CsfO1YpjKLV/wdpBQ2xAnkV5dfFmzlzLOTECgYEAwgJf\n"
  "gxlR9Jgv7Qg/6Prs+SarqT4xDsJKKbD7wH2jveGFXVnkYTPVstwLCAus4LaLFKZ9\n"
  "1POQDUgO24E1GzuL7mqSuvymdl5gZICfpkHstOAfpqep96pUv4aI9BY/g5l4Lvep\n"
  "9c52tgQGwz0qgBUJBi6AvzxqRkBsxrXjX2m7KHUCgYEAtjx94ohkTXWIouy2xFrl\n"
  "jnh9GNGUgyhK7Dfvn3bYjJkwKZc06dkNzvQxdD5r4t3PBhS3YgFWmYmB4X7a6NUF\n"
  "vMMekjlLJkziib1Q1bLDHuLni+WYKmEEaEbepRMrub8h/D0KnQBewwspQoJkxHn3\n"
  "AMkSwurVlwi0DkOa3N+pmTECgYBXyCUZN1qqtjVxJXttWiPg88tWD2q5B9XwmUC/\n"
  "rtlor+LdAzBffsmhXQiswkOdhVrWpCJpOS8jo0f9r6+su7ury5LKgkh7ZGZu8vfJ\n"
  "jSiiCoqnqFMyWWJxKllLP8nLLKSBc9P2AU4bOyUoL8PMIjhsEJx2asqXMM1G98OC\n"
  "R1/EhQKBgQCmSkabsj8u5iEScicyJU87/sVkRIRE0GhjU8uuvcTe+dRiHuj2CENx\n"
  "hh967E0nUCiJzx3is0/nYByDles9W4BLEA8JSuM5r6E7UifHR4XwIi2tQcNhCWIu\n"
  "vGbfvxwqcm7Uj3XHb1GbYK5nnaRNailoJ7iyqHWxB1Q3iFIiMipcfg==\n"
  "-----END RSA PRIVATE KEY-----\n";

/* test server self signed certificates */
const char srv_self_signed_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIICpjCCAZCgAwIBAgIESEPtjjALBgkqhkiG9w0BAQUwADAeFw0wODA2MDIxMjU0\n"
  "MzhaFw0wOTA2MDIxMjU0NDZaMAAwggEfMAsGCSqGSIb3DQEBAQOCAQ4AMIIBCQKC\n"
  "AQC03TyUvK5HmUAirRp067taIEO4bibh5nqolUoUdo/LeblMQV+qnrv/RNAMTx5X\n"
  "fNLZ45/kbM9geF8qY0vsPyQvP4jumzK0LOJYuIwmHaUm9vbXnYieILiwCuTgjaud\n"
  "3VkZDoQ9fteIo+6we9UTpVqZpxpbLulBMh/VsvX0cPJ1VFC7rT59o9hAUlFf9jX/\n"
  "GmKdYI79MtgVx0OPBjmmSD6kicBBfmfgkO7bIGwlRtsIyMznxbHu6VuoX/eVxrTv\n"
  "rmCwgEXLWRZ6ru8MQl5YfqeGXXRVwMeXU961KefbuvmEPccgCxm8FZ1C1cnDHFXh\n"
  "siSgAzMBjC/b6KVhNQ4KnUdZAgMBAAGjLzAtMAwGA1UdEwEB/wQCMAAwHQYDVR0O\n"
  "BBYEFJcUvpjvE5fF/yzUshkWDpdYiQh/MAsGCSqGSIb3DQEBBQOCAQEARP7eKSB2\n"
  "RNd6XjEjK0SrxtoTnxS3nw9sfcS7/qD1+XHdObtDFqGNSjGYFB3Gpx8fpQhCXdoN\n"
  "8QUs3/5ZVa5yjZMQewWBgz8kNbnbH40F2y81MHITxxCe1Y+qqHWwVaYLsiOTqj2/\n"
  "0S3QjEJ9tvklmg7JX09HC4m5QRYfWBeQLD1u8ZjA1Sf1xJriomFVyRLI2VPO2bNe\n"
  "JDMXWuP+8kMC7gEvUnJ7A92Y2yrhu3QI3bjPk8uSpHea19Q77tul1UVBJ5g+zpH3\n"
  "OsF5p0MyaVf09GTzcLds5nE/osTdXGUyHJapWReVmPm3Zn6gqYlnzD99z+DPIgIV\n"
  "RhZvQx74NQnS6g==\n" "-----END CERTIFICATE-----\n";

/* test server key */
const char srv_key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEowIBAAKCAQEAtN08lLyuR5lAIq0adOu7WiBDuG4m4eZ6qJVKFHaPy3m5TEFf\n"
  "qp67/0TQDE8eV3zS2eOf5GzPYHhfKmNL7D8kLz+I7psytCziWLiMJh2lJvb2152I\n"
  "niC4sArk4I2rnd1ZGQ6EPX7XiKPusHvVE6VamacaWy7pQTIf1bL19HDydVRQu60+\n"
  "faPYQFJRX/Y1/xpinWCO/TLYFcdDjwY5pkg+pInAQX5n4JDu2yBsJUbbCMjM58Wx\n"
  "7ulbqF/3lca0765gsIBFy1kWeq7vDEJeWH6nhl10VcDHl1PetSnn27r5hD3HIAsZ\n"
  "vBWdQtXJwxxV4bIkoAMzAYwv2+ilYTUOCp1HWQIDAQABAoIBAArOQv3R7gmqDspj\n"
  "lDaTFOz0C4e70QfjGMX0sWnakYnDGn6DU19iv3GnX1S072ejtgc9kcJ4e8VUO79R\n"
  "EmqpdRR7k8dJr3RTUCyjzf/C+qiCzcmhCFYGN3KRHA6MeEnkvRuBogX4i5EG1k5l\n"
  "/5t+YBTZBnqXKWlzQLKoUAiMLPg0eRWh+6q7H4N7kdWWBmTpako7TEqpIwuEnPGx\n"
  "u3EPuTR+LN6lF55WBePbCHccUHUQaXuav18NuDkcJmCiMArK9SKb+h0RqLD6oMI/\n"
  "dKD6n8cZXeMBkK+C8U/K0sN2hFHACsu30b9XfdnljgP9v+BP8GhnB0nCB6tNBCPo\n"
  "32srOwECgYEAxWh3iBT4lWqL6bZavVbnhmvtif4nHv2t2/hOs/CAq8iLAw0oWGZc\n"
  "+JEZTUDMvFRlulr0kcaWra+4fN3OmJnjeuFXZq52lfMgXBIKBmoSaZpIh2aDY1Rd\n"
  "RbEse7nQl9hTEPmYspiXLGtnAXW7HuWqVfFFP3ya8rUS3t4d07Hig8ECgYEA6ou6\n"
  "OHiBRTbtDqLIv8NghARc/AqwNWgEc9PelCPe5bdCOLBEyFjqKiT2MttnSSUc2Zob\n"
  "XhYkHC6zN1Mlq30N0e3Q61YK9LxMdU1vsluXxNq2rfK1Scb1oOlOOtlbV3zA3VRF\n"
  "hV3t1nOA9tFmUrwZi0CUMWJE/zbPAyhwWotKyZkCgYEAh0kFicPdbABdrCglXVae\n"
  "SnfSjVwYkVuGd5Ze0WADvjYsVkYBHTvhgRNnRJMg+/vWz3Sf4Ps4rgUbqK8Vc20b\n"
  "AU5G6H6tlCvPRGm0ZxrwTWDHTcuKRVs+pJE8C/qWoklE/AAhjluWVoGwUMbPGuiH\n"
  "6Gf1bgHF6oj/Sq7rv/VLZ8ECgYBeq7ml05YyLuJutuwa4yzQ/MXfghzv4aVyb0F3\n"
  "QCdXR6o2IYgR6jnSewrZKlA9aPqFJrwHNR6sNXlnSmt5Fcf/RWO/qgJQGLUv3+rG\n"
  "7kuLTNDR05azSdiZc7J89ID3Bkb+z2YkV+6JUiPq/Ei1+nDBEXb/m+/HqALU/nyj\n"
  "P3gXeQKBgBusb8Rbd+KgxSA0hwY6aoRTPRt8LNvXdsB9vRcKKHUFQvxUWiUSS+L9\n"
  "/Qu1sJbrUquKOHqksV5wCnWnAKyJNJlhHuBToqQTgKXjuNmVdYSe631saiI7PHyC\n"
  "eRJ6DxULPxABytJrYCRrNqmXi5TCiqR2mtfalEMOPxz8rUU8dYyx\n"
  "-----END RSA PRIVATE KEY-----\n";

#endif
