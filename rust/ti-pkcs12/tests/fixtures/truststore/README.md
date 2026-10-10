# Truststore fixture

`openssl-jdktrust.p12` (password `changeit`) is a Java truststore as OpenSSL 4 writes
it: certificate bags only, each with `friendlyName` (Java's alias) and Oracle's trusted
key usage, `anyExtendedKeyUsage`. It holds `../ca-cert.pem` and `../ec-cert.pem`, and
lives outside the fixtures copied from Go:

```sh
cat ../ca-cert.pem ../ec-cert.pem > certs.pem
openssl pkcs12 -export -nokeys -in certs.pem \
    -caname "test ca" -caname "ec.example.com" -jdktrust anyExtendedKeyUsage \
    -passout pass:changeit -out openssl-jdktrust.p12
rm certs.pem
keytool -list -keystore openssl-jdktrust.p12 -storepass changeit   # two trustedCertEntry
```
