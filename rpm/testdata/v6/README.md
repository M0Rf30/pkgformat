# RPM v6 test packages

Built with rpm 6.0.1 from `hello.spec`, a noarch package with a directory, a
regular file `a.txt` containing `hi\n`, and a symlink `b -> a.txt`:

    SOURCE_DATE_EPOCH=1700000000 rpmbuild --define "_topdir $T" \
      --define '_rpmformat 6' --define '_buildhost localhost' \
      --define 'use_source_date_epoch_as_buildtime 1' -bb hello.spec

- `ref-v6.rpm`: unsigned.
- `ref-v6s.rpm`: the same package signed with `rpmsign --addsign` using a
  throwaway key (`pkgformat test`, key ID `1E66303A75B7A873`). rpm 6 stores the
  signature as a base64 OpenPGP packet in signature tag 278 (OPENPGP).
- `testkey.pub`: ASCII-armored public key of the signing key.
