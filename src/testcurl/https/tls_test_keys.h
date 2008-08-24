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
  "MIIEowIBAAKCAQEAthkEJMVt/l06gPJQCfdMKJdYXdQZGSBkOroWGZfs0oYBcSU3\n"
  "JeszCWwDgzw5Ac4o2no9/P7FLVm6+zaIO9gexVi2p1fDhT1+6Lir7O6waS94vLdu\n"
  "jxdJPGfakZTktRAA3MBbC1XuMYPYXZ6nUrRkmHLeG6Oj+L0U3iVq0ZjLYjekCmqV\n"
  "FXRaDmoLWkmxplKz6UyzUXmNlyU4EzLpek2NjTtEUxh0Te+wD4RivBhCPGr7PRlY\n"
  "JhjkTk1u75HP41yQC6MnnfY3IALWwuabBQsreR0W0h17lB3YHdHKjP5xJfEeJPtb\n"
  "625+lHQpH4nfzGcna/RFok6xRpjZu7mB3t7XGwIDAQABAoIBABhD2x5/RHn5uFsI\n"
  "bwv07SwXhsnyAmoru89rjphYe1FOVBDcsa2W2tUtlIY/VyVbcGw0j+APnvy9EUJ6\n"
  "cMrwsKEBgk1oT4CIwkmGmjpXUCCkF8Wl99CPfM3U1PZDTfqmqEbCRx+KktP8Sq+m\n"
  "/YryyNjbracnNilmIMq9V6+YWbm7kJHRLVQWHqh/ljji+kCx5y9VII7HYz4217Er\n"
  "I5HrnPJodmYrH5Tj8Hj9NY7Ok/IeqD186fPuYH/qf9zWcyg7aa0rTPt/E4XjeOjU\n"
  "kxb68+Ybozm0EY1ypa1Yxf3B4hkyrlQ5lfzDSBKqvQkGA92yNDPYiZX71nDHDj9H\n"
  "wf8tWlECgYEAxN8bnMXzmGLbNJUQFuEFBCDFE/tAMhBWcN6eyupIwyXXNA8/xGnJ\n"
  "rYO4U08YrgvQ6d71xLXAJnsypeJ3FsyIXDar21o5DwVj1ON0nW6xuXsfQWYGEsXm\n"
  "fDVf4LVO+P58uAnM3+lKXWMwsw7/ja9VECrOvfTlf7CwwIPfmRzxZEMCgYEA7Mn+\n"
  "PBO352EXzXbGTuLY9iFXo3GL4EXB2nbkXBdTxEbPl+ICjg/1MPtRN9l03y8l06/G\n"
  "MpbxkpPnSXdjXQ1fgXfG9FuKS89BNUfoEfG/3015w49ZAcBYRmvCSGTspu/hshdQ\n"
  "iom2AFy2aRXfvsoUlePRccs1/7RKclK7ahfdwEkCgYBXQOLGCt25rialGWO2ICjO\n"
  "+Y8fGf4Lsj39bE1IdammBAFrK08ByDkAVB6/nZC8orQG0zBt7HerFnMOHl7VlfTh\n"
  "mcF1SHl9dNAYLG8kz0ipgi4KGCOc8mUCq81AlFrZ9EBmeMF6g7TXyvxsf7s3mnvC\n"
  "3JYgjoegnjjYOhpBjBhYbQKBgQCpwJmBakVyG/obcyXx0dDmirqwUquLaZbyzj8i\n"
  "AhssX/NdGErqm2gU6GauWjfd9IfyvVWiWPHwOhYaZfuW7wpj34GDFskLVhaSYu1t\n"
  "R9lc9cbwOqj9h24Bdik/CxNZDinIKcy0tMsEcXLX3TWdKnQdjMhPAvbATPj+Am+X\n"
  "PGrd+QKBgF5U2i0d2Mgw/JmlVCY79uD9eERivF5HLOYv3XUr9N1/bgIqKSQnrKJC\n"
  "pXC+ZHP9yTmcznwFkbMbJ9cTwMVU1n+hguvyjIJHmmeGrpBuaiT4HwPgV6IZY3N2\n"
  "a05cOyYYE3I7h9fQs1MfZRK44rRiXycwb+HA4lwuFWTI7h5qdc/U\n"
  "-----END RSA PRIVATE KEY-----\n";

/* Certificate Authority cert */
const char ca_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIC6DCCAdKgAwIBAgIESJ2sXDALBgkqhkiG9w0BAQUwFzEVMBMGA1UEAxMMdGVz\n"
  "dF9jYV9jZXJ0MB4XDTA4MDgwOTE0NDAyOFoXDTA5MDgwOTE0NDAyOFowFzEVMBMG\n"
  "A1UEAxMMdGVzdF9jYV9jZXJ0MIIBHzALBgkqhkiG9w0BAQEDggEOADCCAQkCggEA\n"
  "thkEJMVt/l06gPJQCfdMKJdYXdQZGSBkOroWGZfs0oYBcSU3JeszCWwDgzw5Ac4o\n"
  "2no9/P7FLVm6+zaIO9gexVi2p1fDhT1+6Lir7O6waS94vLdujxdJPGfakZTktRAA\n"
  "3MBbC1XuMYPYXZ6nUrRkmHLeG6Oj+L0U3iVq0ZjLYjekCmqVFXRaDmoLWkmxplKz\n"
  "6UyzUXmNlyU4EzLpek2NjTtEUxh0Te+wD4RivBhCPGr7PRlYJhjkTk1u75HP41yQ\n"
  "C6MnnfY3IALWwuabBQsreR0W0h17lB3YHdHKjP5xJfEeJPtb625+lHQpH4nfzGcn\n"
  "a/RFok6xRpjZu7mB3t7XGwIDAQABo0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud\n"
  "DwEB/wQFAwMHBAAwHQYDVR0OBBYEFGTWojUUrKbS/Uid9S3hPxmgKeaxMAsGCSqG\n"
  "SIb3DQEBBQOCAQEAWP1f/sfNsvA/oz7OJSBCsQxAnjrKMIXgbVnop+4bEWPxk4e9\n"
  "TETSk5MMXt2BfaCtaLZw19Zbqlh4ZFuVw+QC1GTa0xlagHiRgXU2DOvPT5+y+XUR\n"
  "TSy0Pqou7spgEkLcFxlXYlx3tpDu+Awmx9DBGHMCysVynnEzeBYW4woCfBG2UiVA\n"
  "iHVz6jBc4bBkylKVkA42GiroExuPc+W9qtHGuVX045R7gz78KK0CMIObdySbogBe\n"
  "gYZUbyVvPVHINEc929PoV12dHP7wrKnqPbiwb+h1SHui8bVinE+1JY3mRB1VGVTa\n"
  "rgvlVGs2S+Zq48XMs4aeLgHkGWFAIXbpX34HSw==\n" "-----END CERTIFICATE-----\n";

/* test server CA signed certificates */
const char srv_signed_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDBDCCAe6gAwIBAgIESJ2sXzALBgkqhkiG9w0BAQUwFzEVMBMGA1UEAxMMdGVz\n"
  "dF9jYV9jZXJ0MB4XDTA4MDgwOTE0NDAzMloXDTA5MDgwOTE0NDAzNVowADCCAR8w\n"
  "CwYJKoZIhvcNAQEBA4IBDgAwggEJAoIBAOb6G6WJrrNC48NSh5i4eT7J1BCqlMB4\n"
  "e0No+td/PQf+sPywbQToYGiPfOFfMyge1G6SyRpXavKbPwuw1BN183WoYzID5mtz\n"
  "shAOl/JRhdusScFijS3pITiNK4G5NLToCP4KZhqguqHUzEdanifSb/D4x54Rq/Tc\n"
  "A7oHGp0wjdWC/AMtGWv6v55xMe00ALZ1zDxCOi8nri9W7mLy+hyduETCq+1Y7uHl\n"
  "mqbAk8D7ruu0JtNU2N8WuJJcAtxgZhCCfIHTgAUWqepeRBM8cy8uu0tywgxcJiyt\n"
  "Uu1wXQHnnpWrr/9r6IfhjFpc9pr5giHBeM4KdlU49UsYgaS1tAZsDJcCAwEAAaN2\n"
  "MHQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8BAf8E\n"
  "BQMDB6AAMB0GA1UdDgQWBBSxP229okDqlKyMCyg0cnzbf+eb4DAfBgNVHSMEGDAW\n"
  "gBRk1qI1FKym0v1InfUt4T8ZoCnmsTALBgkqhkiG9w0BAQUDggEBAEabY4FLsFQr\n"
  "PACNe3p5tU3hWvvQ9S1pRlfnc/z1o+k9NDWTHlNjXfVTl6/6cIKHA+r8SvRks27+\n"
  "lScfxFkiCi22YC7uPbn8fW1nWcsqEkK4e0TDekSUi1o6SDx6cU07kMpx3iKvpLs3\n"
  "5QiCFjivMjrY8pEFJIke/ucI8QuLVZLLUSdTHb9Ck128PtPKA4y2uZA/MmYS/OtR\n"
  "/UZN67pJ+BqcQBE5vNolWQTM+NxfMzb48IV9q32HRT4HErvUjLIWV0nwwedUSdDG\n"
  "63tr9jp0GF6b5Eum0MTVV/zbBxfyRFg+Q8xRn70zJlB/W7byaFq/95Rpfqjdnta2\n"
  "aO/omlvGHrI=\n" "-----END CERTIFICATE-----\n";

/* test server key */
const char srv_signed_key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEowIBAAKCAQEA5vobpYmus0Ljw1KHmLh5PsnUEKqUwHh7Q2j61389B/6w/LBt\n"
  "BOhgaI984V8zKB7UbpLJGldq8ps/C7DUE3XzdahjMgPma3OyEA6X8lGF26xJwWKN\n"
  "LekhOI0rgbk0tOgI/gpmGqC6odTMR1qeJ9Jv8PjHnhGr9NwDugcanTCN1YL8Ay0Z\n"
  "a/q/nnEx7TQAtnXMPEI6LyeuL1buYvL6HJ24RMKr7Vju4eWapsCTwPuu67Qm01TY\n"
  "3xa4klwC3GBmEIJ8gdOABRap6l5EEzxzLy67S3LCDFwmLK1S7XBdAeeelauv/2vo\n"
  "h+GMWlz2mvmCIcF4zgp2VTj1SxiBpLW0BmwMlwIDAQABAoIBACJGvGKQ74V3qDAc\n"
  "p7WwroF0Vw2QGtoDJxumUQ84uRheIeqlzc/cIi5yGLCjPYa3KIQuMTzA+0R8aFs2\n"
  "RwqKRvJPZkUOUhvhA+whFkhl86zZQOq7UsMc5Qqs3Gd4UguEoYz9gxBxiLCqURRH\n"
  "rM+xCV6jtI/PBIsmOUFae4cXJP0pljUXyYmwwb/WrsvnJXf9Gz8/VLZGBMchMH7R\n"
  "MwD7xdwc/ht2XfZ0TuDntpJDtj0JrW9i/Cxt8PnNhQjgLsAe+oUUZt7Bo+vXBxhu\n"
  "JPKj6BHcj768l+gDn5zzaXKq0eF7mMXc7fgAp0u8lJkC0LxLq/WmIfqw4Z4mEjkX\n"
  "DremIoUCgYEA53vX9Hd8V85hCfeaTDf3B5q6g9kIliR+Y2tX2aSqN06df9J/KOdL\n"
  "G/lEQn4rsOOtOwyTU2luPmcr0XgbXA1T1kj56+UZrxtRducsdsVbVixzD2KswtJO\n"
  "wUH6XAJNdpI++64TuZadnKAaKiqim7CPzQYrBXYKKRFGSDd50urkTRMCgYEA/3CG\n"
  "NMaG3qtzQceQUw7BBAhey387MR+1FUQHQ7xoq2jc3yAx4H2NEyGa6wL5CtFKn5In\n"
  "BP6f30sk2ilXRv5pbIIiS8Xzngxy3m17GH33YrSc3ff/u+LWgR/EOVpa9F+sMAjp\n"
  "ohDgI8iH8GtahrRA0BxQKfNIo2zUTqNwFP88xu0CgYADOY1zoWqBCqX9bo6euzTc\n"
  "zUIF7jMZbF66Yddyd8HLTXQSQMt2tWotdJaH2pwfNbzHEtDGm7RmeCd7HpI7ARCG\n"
  "7rNUnvdxog7LekL7UJqKI8pij3xapnVkadfkCkAsA7OO7AjoT/nYIb7bkYZ8ZsRK\n"
  "FejphZB0rAHvpZ4z2wPdMwKBgQCfkr70RzVH81lcNXwutt/TUhtOCxyCMqmgMFBN\n"
  "e2zz791TMjyWXjh8RBkQSVok7NwuVVI055AeIUZTV1IjkplvZNhh97aZ/HLiCwjE\n"
  "IyUhL21zqRLEYA/auGqP3adGVGIv29GAIgSztfleMuJplj+LArT9j/LHzRvQSH+j\n"
  "TlO8fQKBgE5og4pTfPrD0A7W/Li1HDGf8Ylb+DZlxoyMriW82Z/zCBvYvn1UvQRi\n"
  "b8f3IQFXuXdf3Bx4C91kQJPovxDp14FOHJxO7F32fGMnJaU2kyp4sf4WAJZZOLnd\n"
  "l64hMUsgYPI8qfsanAudD4gTAsLEP+ueWqkcb3SJNLSoQAtcGzYs\n"
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
