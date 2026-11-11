# createrepo_c corpus

`Packages/` holds real packages with their payload removed (`strip.go`): 28
Fedora 45 rpms (rpm 4 headers: weak and rich dependencies, file triggers,
ghost files, epochs, `^` and `~` in versions, multi-arch pairs) and rpmbuild
6.0.1 packages built for this test (rpm 4 and rpm 6 headers, rich
dependencies, empty and special-character fields).

`golden/` is the output of `createrepo_c 1.2` for them (see `gen.sh`:
`--simple-md-filenames --filelists-ext`, file times fixed to 1700000000). The
tests assert the documents the package writes are byte-identical.
