# Test installed databases

Two real `/lib/apk/db/installed` files, one written by apk-tools 3 and one by
apk-tools 2, so that both layouts are tested. `generate.sh` rebuilds them; it
needs podman or docker and network access.

| Directory | Image | apk | Added to the image |
| --- | --- | --- | --- |
| `alpine-3.24` | `alpine:latest` (Alpine 3.24.3) | apk-tools 3.0.8 | the virtual package `.build-deps` with `zlib-dev` |
| `alpine-3.20` | `alpine:3.20` (Alpine 3.20.10) | apk-tools 2.14.4 | `curl` and its dependencies |

The virtual package has a name no index entry has (it starts with a dot) and
no files. The apk 2 database has the `r`, `q` and `k` lines, the apk 3 one the
`a` and `M` lines for every file and directory with an owner and a mode.

## Files

| File | Content |
| --- | --- |
| `installed` | `/lib/apk/db/installed`, as apk left it |
| `list.expected` | `apk list -I`: name-version, architecture, origin, license |
| `files.expected` | `apk info -L` for every package |
| `provides.expected` | `apk info -P` for every package |
| `depends.expected` | `apk info -R` for every package |
| `info.txt` | the Alpine release and the apk version |

The `apk` commands run with `--no-network`, so that they answer from the
installed database and not from the repository index the `apk add` fetched,
which may hold newer versions. The tests decode `installed` and compare each
package with what these print.
