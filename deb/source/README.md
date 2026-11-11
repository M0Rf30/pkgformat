# deb/source

Debian source packages and the documents around them, in pure Go.

| Document | Read | Write | Sign / verify |
| --- | --- | --- | --- |
| `.dsc` (formats 1.0, 3.0 quilt, 3.0 native, 3.0 git as metadata) | `ParseDSC`, `ReadDSC` | `DSC.Marshal` | `DSC.Sign`, `ParseSignedDSC` |
| Sources index (plain, gzip, xz, zstd, bz2, lz4 on read) | `ReadSources` | `WriteSources`, `IndexSources` | |
| `.changes` (format 1.8) | `ParseChanges`, `ReadChanges` | `Changes.Marshal` | `Changes.Sign`, `ParseSignedChanges` |
| `.buildinfo` (format 1.0) | `ParseBuildInfo`, `ReadBuildInfo` | `BuildInfo.Marshal` | `BuildInfo.Sign`, `ParseSignedBuildInfo` |

| Source package | Unpack | Build |
| --- | --- | --- |
| 1.0 (`.orig.tar.gz` + `.diff.gz`, or one tarball) | `Unpack` | |
| 3.0 (quilt) with component tarballs and `.asc` signatures | `Unpack`, patches applied at fuzz 0 | `Build` |
| 3.0 (native) | `Unpack` | `Build` |

```go
d, err := source.ParseSignedDSC(data, keyring)          // verify, then parse
err = source.Unpack(d, "downloads", "hello-2.10", nil)  // like dpkg-source -x
res, err := source.Build("hello-2.10", &source.BuildOptions{OutDir: "out"})
```

Documents carry the fields they do not model in `Extra`, so a parse and
marshal keeps them. `Marshal` writes the field order of dpkg.

## Security

Unpacking untrusted source packages is bounded and contained: every file is
checked against the digests of the `.dsc` first; entries are extracted under
the target with `safepath` (no `..`, no symlink components, no device nodes,
no hard links out of the tree); `UnpackOptions` bounds entries and bytes;
patches are applied by `ApplyPatch` which never follows a symlink and writes
only inside the tree. Documents are limited to `MaxDocumentBytes`; compressed
indexes to `deb.MaxIndexBytes`. Errors wrap the sentinels in `errors.go`.

## Interoperability proofs

Fixtures live in `testdata`, with the scripts that made them. No file name
contains a colon.

| Claim | Proof |
| --- | --- |
| `Unpack` equals `dpkg-source -x` for 12 real Debian packages (quilt, native, 1.0, component, `.asc`) | `testdata/expected/*.manifest` from `generate.sh`; `TestUnpackMatchesDpkgSource` runs the tool |
| `Build` output is accepted by `dpkg-source -x`, and matches `dpkg-source -b` (file list, digests, `.dsc`) | `TestBuildMatchesDpkgSource` |
| `.dsc` marshal equals the dpkg-source output byte for byte | `TestDSCMarshalMatchesDpkgSource` |
| Sources index equals `apt-ftparchive sources`, and `dpkg-scansources` stanza by stanza | `testdata/sources`, `generate-sources.sh`, live comparison test |
| `.changes` and `.buildinfo` marshal equal `dpkg-genchanges` and `dpkg-genbuildinfo` from a real container build | `testdata/changes`, `generate-changes.sh` |
| Signatures interoperate with `gpg` | `TestSignedDocumentsInteropWithGPG` |

See `testdata/README.md` for where each fixture comes from.
