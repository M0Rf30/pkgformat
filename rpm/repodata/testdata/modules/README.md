# modules.yaml fixtures

Regenerate with `sh generate.sh` (needs `curl`, `xz`, `gzip`, `python3`, the
libmodulemd python bindings and `modulemd-validator`; the network is used only
there, the tests read the committed files).

Tools used for the committed files: libmodulemd 2.15.4 (python `gi`
`Modulemd-2.0` and `modulemd-validator`), curl, xz 5.x, gzip.

| File | Source | What it covers |
| --- | --- | --- |
| `rocky9-appstream.yaml` | Rocky Linux 9 AppStream x86_64 `modules.yaml` (`https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/repodata/5bc2523233617a7e5a22db1c3df821be29deead4a2e6016392b4461c8f3237b7-modules.yaml.xz`), trimmed by `trim_modules.py` to `nginx` 1.22 and 1.26, `mariadb` 10.11 and `maven` 3.9 with their defaults; documents are copied byte for byte | numeric `context`, unquoted `1.22` keys, profiles, default profiles, dependencies, references, api, filter, rpm components, artifacts, buildopts with macros, xmd |
| `rocky8-appstream.yaml` | Rocky Linux 8 AppStream x86_64 `modules.yaml` (`https://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/repodata/bc0c446faa2133f807dcb66088e0eba3b12bdf880cccae3a8207832ced11cae8-modules.yaml.xz`), trimmed to `go-toolset`, `llvm-toolset`, `ruby` 2.5 and `nodejs` 10 with their defaults | dependencies, references, api, rpm components, artifacts, buildopts with macros, xmd |
| `fedora38-obsoletes.yaml` | Fedora 38 updates Modular x86_64 `modules.yaml` (`https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/38/Modular/x86_64/repodata/94bf64c1dcb8a99560d1c57ae4814ea5a1736e822976ca3d8e11228c19a8be79-modules.yaml.gz`), trimmed to the obsoletes of `cri-o` 1.10, `perl` 5.30 and `perl-IO-Socket-SSL` 2.068 | `modulemd-obsoletes` v1 with `eol_date`, `message`, `obsoleted_by` |
| `spec-stream-v2.yaml`, `spec-defaults-v1.yaml`, `spec-obsoletes-v1.yaml`, `spec-translations-v1.yaml` | the format examples of libmodulemd 2.15.4 (`https://raw.githubusercontent.com/fedora-modularity/libmodulemd/2.15.4/yaml_specs/modulemd_{stream_v2,defaults_v1,obsoletes_v1,translations_v1}.yaml`) | every field of every document kind: `rpm-map`, module components, service levels, translations |
| `*.libmodulemd.yaml` | `libmodulemd_dump.py`: what `Modulemd.ModuleIndex.dump_to_string()` writes for the file of the same name | the reference output the Go writer must match byte for byte (translations with several locales are compared after parsing: libmodulemd orders locales by hash) |

`modulemd-validator` accepts every file here, the `*.libmodulemd.yaml`
references included (`generate.sh` checks it).

Not in the model: `srpm-nevras`. The example of libmodulemd's own specification
has no such key and `modulemd-validator` 2.15.4 rejects it ("Unexpected key in
map").
