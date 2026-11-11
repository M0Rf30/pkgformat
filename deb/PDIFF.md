# pdiff: `Packages.diff` in package `deb`

A Debian repository can publish, next to an index file (`Packages`, `Sources`,
`Contents-<arch>`, `Translation-<lang>`), a directory `<index>.diff/` of small
ed-script patches. A client that holds a recent copy of the index downloads a
few kilobytes of patches instead of the whole file. This package implements
both sides: reading and applying patches (what `apt` does) and producing them
(what `dak` does).

```
dists/stable/main/binary-amd64/
    Packages.xz                     the index
    Packages.diff/Index             the list of patches, with digests
    Packages.diff/2026-05-01-1234.56.gz       patch files
```

The `Release` file lists `Packages.diff/Index` (and the uncompressed `Packages`)
with their hashes; apt checks the Index against it and the patched file against
the `Current` hash of the Index.

## Reading: Index, chain, apply

```go
idx, err := deb.ParsePDiffIndex(indexData)       // Packages.diff/Index
chain, err := idx.Chain(deb.PDiffSHA256(local))  // patches from the local file to Current
if errors.Is(err, deb.ErrPDiffNoPath) { /* fetch the whole index */ }
fresh, err := deb.ApplyPDiffChain(local, chain, fetch, deb.PDiffApplyOptions{})
```

* `PDiffIndex` carries `Current`, `Patches` (the `History` list: each entry is
  the digest of the file the patch applies to), the `X-Unmerged-*` series of a
  merged Index, `X-DAK-Older-Patches`, `Canonical-Path` and unknown fields
  (`Extra`). SHA-256 and legacy SHA-1 sections are read; `Marshal` writes the
  layout dak writes, byte for byte for the real Indexes in `testdata`.
* `Chain` starts at the newest history entry whose digest is the local file
  (so a history that went back to an old state is handled), returns an empty
  chain for the current file, and `ErrPDiffNoPath` otherwise. In a merged Index
  (`X-Patch-Precedence: merged`) every patch leads to the current file and the
  chain has one patch. `PDiffPatch.To` is the digest of the file after the
  patch.
* `ApplyPDiffChain` verifies every step: the base, the downloaded `.gz`
  (size, SHA-256), the script (size, SHA-256) and the patched file (`To`). A
  mismatch is a `*PDiffHashError` (`errors.Is(err, ErrPDiffHash)`); nothing
  unverified is carried to the next patch.

## Applying a script

`ApplyPDiff`, `ApplyPDiffWith` and the streaming `ApplyPDiffTo(dst, base,
patch, opts)` apply the subset of ed that diff and dak produce: `Na`, `N,Mc`,
`Nd`, text lines up to a lone `.`, commands from the end of the file to its
start without overlap (the rule rred, apt's applier, enforces). Everything else
-- other ed commands, ascending or overlapping commands, line 0 for anything
but `a`, an unterminated text block, a range past the end of the file -- is a
`*PDiffError` (`errors.Is(err, ErrPDiffScript)`) with the script line. `Line`
is 0 for an error about the file, not the script.

* The base is streamed; memory is proportional to the script. Limits
  (`PDiffApplyOptions`): patch size (default 256 MiB), result size (default
  `MaxIndexBytes`), number of commands (default 2^21); over a limit the error
  is `ErrPDiffLimit`.
* Bytes of the base that are kept are copied unchanged, like rred does. For a
  base without a final newline that means text appended after its last line
  follows it directly (ed would add the newline); measured with apt 2.6.2.
  Real indexes end in a newline.

## Making patches

`GeneratePDiff(old, new)` returns the ed script that turns `old` into `new`, in
dak's layout (descending commands). It is a line diff with Myers' linear-space
algorithm, so the script changes the fewest lines possible (checked against a
dynamic-programming LCS in the tests); `PDiffGenerateOptions` bounds the line
count and the edit distance (beyond it the differing middle is replaced as one
hunk, which is still correct). A script cannot add a line that is just `.` or a
last line without a newline: `ErrPDiffUnrepresentable`.

`MergePDiffs(p1, p2, ...)` composes scripts into one with the effect of applying
them in turn, as `rred -f p1 p2 ...` does; it is what merged Indexes are made of.

## Publishing: `PDiffIndexBuilder`

```go
dir, _ := deb.NewPDiffDirFS("repo/dists/stable/main/binary-amd64") // or NewPDiffMemFS
builder, _ := deb.NewPDiffIndexBuilder(dir, deb.PDiffBuilderOptions{})

// before the new Packages replaces the old one:
res, err := builder.Update(newPackages, time.Now())
// ... then write Packages, Packages.xz; list res.IndexData as
// main/binary-amd64/Packages.diff/Index in the Release.
```

`Update` reads the old file from the `PDiffFS` (`Packages`, or `.xz`, `.gz`,
`.zst`, `.bz2`, `.lz4`), diffs it against the new content, writes the gzip patch
(`2006-01-02-1504.05` UTC name; the next free second on collision), adds it to
the history, prunes to `MaxPatches` (default 56), rewrites the Index and deletes
the patch files that fell out of it. Patch files are written first and the
Index last, atomically, so a client always finds an Index whose patches exist.
`UpdateFrom(old, new, now)` takes the old content instead.

* `Merge: true` publishes merged patches (`T-<new>-F-<orig>`, `X-Unmerged-*`,
  `X-Patch-Precedence: merged`, `X-DAK-Older-Patches` keeping the files of the
  last three series). Every update rewrites all patches. Switching between
  merged and unmerged keeps working.
* `SHA1` lists legacy digests; `XZ` also publishes `.xz` downloads (apt reads
  only `.gz`).
* The builder heals itself: a history that does not end at the old file, a
  missing or damaged patch file or a corrupt Index starts the history over with
  the new patch (`PDiffUpdate.Reset`). A change no patch can express (or one
  over the generator's limits) removes the history and publishes none
  (`PDiffUpdate.Skipped`): clients then fetch the whole file, which is always
  correct.
* Output is deterministic (gzip without name and time in the header).

`PDiffFS` is the storage abstraction (`ReadFile`, `WriteFile`, `Remove`,
`ReadDir`); `NewPDiffDirFS` works inside an `os.Root` so no name escapes the
directory.

## Verification

| What | Where |
|---|---|
| Real Indexes (merged and unmerged) parse, chain, apply, and `Marshal` reproduces them | `testdata/repo-pdiff/{buster,trixie}-updates`, `TestPDiffReal*` |
| Every real patch on every real base equals rred's output (or both refuse) | `testdata/repo-pdiff/rred-matrix.txt`, `TestPDiffRredMatrix` |
| Generated patches applied by rred and GNU ed give the new file | `testdata/repo-pdiff/interop*`, `generate.sh`, `TestPDiffInteropAgainstRredAndEd`, `TestPDiffRredLive` |
| `apt-get update` fetches and applies what the builder publishes (apt 2.6.2, 3.0.4) | `testdata/repo-pdiff-e2e`, `TestPDiffAptE2E` (`PKGFORMAT_E2E=1`) |
| Parser, applier, generator, merger fuzzed | `FuzzParsePDiffIndex`, `FuzzApplyPDiff`, `FuzzGenerateApply`, `FuzzMergePDiffs` |
