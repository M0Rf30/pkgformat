# Package signature fixtures

Packages signed by the reference tools, to check `SignPackage` and
`VerifySignatures` against them. `generate.sh` rebuilds everything in a Debian
bookworm container (`Containerfile`; dpkg-sig comes from the Debian archive
pool, because current releases no longer ship it).

| File | Made by |
| --- | --- |
| `unsigned.deb` | `dpkg-deb --root-owner-group -Zgzip --build`, `SOURCE_DATE_EPOCH=1700000000` |
| `real-debsigs.deb` | `debsigs --sign=origin` (member `_gpgorigin`) |
| `real-dpkg-sig.deb` | `dpkg-sig -s builder` (member `_gpgbuilder`) |
| `pub.asc`, `pub.gpg` | public key, armored and binary |
| `key.asc` | private key of the throw-away test key, no passphrase; it signs nothing but these fixtures |
| `fingerprint.txt` | fingerprint of that key |
| `policy.pol` | the `debsig-verify` policy for the key |
| `real-tools.txt` | output of `debsig-verify` and `dpkg-sig --verify` on the two signed packages |

The key is generated on every run, so regenerating changes every binary here.
`debsigs` signs with gpg's default digest, which is SHA-1 on gpg 2.2 and which
`debsig-verify` rejects; `inner.sh` sets `digest-algo SHA256` in `gpg.conf`.
