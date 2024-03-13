# cert-manager Booth Guestbook

## Setup

1. Manually copied a locally built guestbook binary, litestream.yml, the systemd service, the cert, key and CA files to the remote VM.
2. Installed litestream manually, then moved litestream.yml to /etc/litestream.yml
3. Moved the systemd unit to /usr/lib/systemd/system
4. Created /var/guestbook
5. Ran the guestbook with init-db to create the db, moved it to /var/guestbook
6. Enabled litestream and the systemd unit

## Root CA

The root CA for the whole booth demo is below:

```text
-----BEGIN CERTIFICATE-----
MIIB7TCCAZOgAwIBAgIRAJ0xoqVXNnNYDT5ZomjDrnAwCgYIKoZIzj0EAwIwVTEN
MAsGA1UEChMEQ05DRjEVMBMGA1UECxMMY2VydC1tYW5hZ2VyMS0wKwYDVQQDEyRU
aGUgY2VydC1tYW5hZ2VyIG1haW50YWluZXJzIFJvb3QgQ0EwIBcNMjQwMzE1MTcw
NjU5WhgPMjEyNDAyMjAxNzA2NTlaMFUxDTALBgNVBAoTBENOQ0YxFTATBgNVBAsT
DGNlcnQtbWFuYWdlcjEtMCsGA1UEAxMkVGhlIGNlcnQtbWFuYWdlciBtYWludGFp
bmVycyBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIHB+NLHy2VDv
QyPUVY7tPlQxfQla1dAMZGpJTy/omh3KYjDAnkW3HQYLoCOunGvdueZcGj7TC/6h
uA2FJpMgqqNCMEAwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFDUCC+tbCj9UK7ucreYunGkKnwGmMAoGCCqGSM49BAMCA0gAMEUCIQDC
dHkfIZx5ZNiZ2B0bdI9BfgGb+/kQW2ZXzLwm/FP6QAIgZq2wn5fZVux8ZXF7Bx22
ZEpst23GWAwfamTUmBLlgFA=
-----END CERTIFICATE-----
```

```text
Certificate:
  Data:
    Version: 3 (0x2)
    Serial Number:
        9d:31:a2:a5:57:36:73:58:0d:3e:59:a2:68:c3:ae:70
    Signature Algorithm: ecdsa-with-SHA256
    Issuer: O=CNCF, OU=cert-manager, CN=The cert-manager maintainers Root CA
    Validity
        Not Before: Mar 15 17:06:59 2024 GMT
        Not After : Feb 20 17:06:59 2124 GMT
    Subject: O=CNCF, OU=cert-manager, CN=The cert-manager maintainers Root CA
    Subject Public Key Info:
      Public Key Algorithm: id-ecPublicKey
        Public-Key: (256 bit)
        pub:
          04:20:70:7e:34:b1:f2:d9:50:ef:43:23:d4:55:8e:
          ed:3e:54:31:7d:09:5a:d5:d0:0c:64:6a:49:4f:2f:
          e8:9a:1d:ca:62:30:c0:9e:45:b7:1d:06:0b:a0:23:
          ae:9c:6b:dd:b9:e6:5c:1a:3e:d3:0b:fe:a1:b8:0d:
          85:26:93:20:aa
        ASN1 OID: prime256v1
        NIST CURVE: P-256
    X509v3 extensions:
      X509v3 Key Usage: critical
        Digital Signature, Key Encipherment, Certificate Sign
      X509v3 Basic Constraints: critical
        CA:TRUE
      X509v3 Subject Key Identifier:
        35:02:0B:EB:5B:0A:3F:54:2B:BB:9C:AD:E6:2E:9C:69:0A:9F:01:A6
  Signature Algorithm: ecdsa-with-SHA256
  Signature Value:
    30:45:02:21:00:c2:74:79:1f:21:9c:79:64:d8:99:d8:1d:1b:
    74:8f:41:7e:01:9b:fb:f9:10:5b:66:57:cc:bc:26:fc:53:fa:
    40:02:20:66:ad:b0:9f:97:d9:56:ec:7c:65:71:7b:07:1d:b6:
    64:4a:6c:b7:6d:c6:58:0c:1f:6a:64:d4:98:12:e5:80:50
```
