# Keyring fixtures for Signed-By

Keys and clear-signed files made by the real `gpg` (GnuPG 2.4.9, see
`gpg-version.txt`) with `generate.sh` in this directory, for the `LoadKeyring`
tests (fingerprint, keyring path, directory and inline forms of Signed-By).

| File | Content |
| --- | --- |
| `a.asc`, `a.gpg` | Public key A (ed25519, signing primary key), armored and binary |
| `b.asc` | Public key B (ed25519, signing primary key) |
| `c.asc` | Public key C: a certify-only ed25519 primary key with an ed25519 signing subkey |
| `bc.gpg` | Keys B and C in one binary keyring |
| `fingerprints.txt` | `A`, `B`, `C` and `C-subkey` fingerprints, one `name fingerprint` per line |
| `signed-by-a.txt` | Clear-signed text signed by A |
| `signed-by-b.txt` | Clear-signed text signed by B |
| `signed-by-c-subkey.txt` | Clear-signed text signed by the signing subkey of C |

All keys are throw-away and never expire. The tests read the fingerprints from
`fingerprints.txt`, so regenerating (`generate.sh`, which makes new keys) needs
no code change. The tests prove that `LoadKeyring` returns a keyring that
verifies exactly the files signed by the selected keys: a fingerprint selects
the key and its subkeys, a trailing `!` the key alone (so the subkey signature
no longer verifies), a subkey fingerprint that subkey.
