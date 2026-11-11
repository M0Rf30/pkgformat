# Files database

`repo-add --include-sigs` of the package of `../makepkg` with a detached
signature made by a throw-away ed25519 key, and what `pacman -Fy`, `-Fl` and
`-F` print for it from a `file://` repository (`generate.sh`, host tools:
repo-add 7.1.0, pacman 7.1.0, gpg 2.4.9).

| File | Content |
| --- | --- |
| `repo.db.tar.gz` | the sync database (no `files` members) |
| `repo.files.tar.gz` | the files database repo-add writes next to it |
| `package.sig` | the signature stored as `%PGPSIG%` |
| `Fl.expected` | `pacman -Fl tree-shapes` |
| `F.expected` | `pacman -F usr/bin/shape-sym` |
| `info.txt` | versions |

repo-add 7.1 no longer writes `%MD5SUM%`; the writer still does, for older
pacman versions, and the tests leave it out when comparing members.
