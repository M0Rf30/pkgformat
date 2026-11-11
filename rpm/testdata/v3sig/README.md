# Version 3 OpenPGP signatures

- `basesystem-10.0-7.el7.centos.noarch.rpm`: CentOS 7.9.2009 package, from
  <https://vault.centos.org/7.9.2009/os/x86_64/Packages/>. Its RSAHEADER and
  SIGPGP tags hold version 3 RSA/SHA256 signature packets.
- `RPM-GPG-KEY-CentOS-7`: the signing key, from
  <https://vault.centos.org/7.9.2009/os/x86_64/RPM-GPG-KEY-CentOS-7>.

`rpmkeys -Kv` of the CentOS 7 image (`quay.io/centos/centos:centos7`) reports
both signatures OK:

```text
Header V3 RSA/SHA256 Signature, key ID f4a80eb5: OK
V3 RSA/SHA256 Signature, key ID f4a80eb5: OK
```
