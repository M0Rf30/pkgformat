# Test dpkg status file

A real `/var/lib/dpkg/status`, written by dpkg 1.22.22 in a `debian:stable-slim`
container (Debian 13.7), after a few packages were installed, removed and held.
`generate.sh` rebuilds it; it needs podman or docker and network access.

| Stanza | `Status` | Why it is there |
| --- | --- | --- |
| 88 packages | `install ok installed` | the usual case |
| `hello` | `hold ok installed` | on hold: installed in dpkg's own terms |
| `less` | `install ok unpacked` | unpacked, not configured: not installed |
| `wget` | `deinstall ok config-files` | removed, configuration kept: not installed |
| `libgcc-s1:i386`, `libc6:i386`, ... | `install ok installed` | a second architecture, `Multi-Arch: same` |

`tree` was installed and purged; dpkg 1.22 removes the stanza of a purged
package, so there is no `purge ok not-installed` in the real file (the tests
build that case by hand). The file keeps its `Conffiles:` lists, a field whose
first line is empty, which the round-trip test writes back byte for byte.

## Files

| File | Content |
| --- | --- |
| `status` | `/var/lib/dpkg/status`, as dpkg left it |
| `status.expected` | `dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${Status}\t${Provides}\n'`, one line per stanza, in file order |
| `info/<pkg>.list` | `/var/lib/dpkg/info/<pkg>.list` of a few packages (`libgcc-s1:amd64`, `libgcc-s1:i386` and `libc6:i386` for Multi-Arch) |
| `info/<pkg>.expected` | `dpkg-query -L <pkg>` for the same |
| `info.txt` | the Debian release and the dpkg version |

The tests decode `status` and compare each entry with its `.expected` line.
