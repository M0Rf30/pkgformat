# prestodelta.xml corpus

Output of a real `createrepo_c --deltas` run, used to check that the reader
and the writer of `deltainfo.go` agree with it.

- `old/` holds the older versions of three test packages (`delta-demo` 1.0 and
  1.1 with epoch 1, `delta-lib` 2.3-4.el9 without epoch) and `repo/` the
  newest versions, a package without older versions (`delta-solo`), the delta
  rpms in `repo/drpms/` and the metadata in `repo/repodata/`.
- `prestodelta.xml` is the uncompressed `repo/repodata/prestodelta.xml.gz`.
  It lists two deltas for `delta-demo` (the two older versions) and one for
  `delta-lib`; `delta-solo` has none and does not appear.

Tools (`generate.sh` rebuilds everything, the result is reproducible):

| step | tool |
| --- | --- |
| rpms | rpmbuild 6.1.0 in `localhost/s3tools:latest` (Fedora, `SOURCE_DATE_EPOCH=1700000000`) |
| delta rpms and `prestodelta.xml` | createrepo_c 1.2.6 on the host (`Features: DeltaRPM`, drpm library) |

The command is

    createrepo_c -q --deltas --num-deltas 2 --oldpackagedirs old \
        --simple-md-filenames --general-compress-type=gz \
        --revision 1700000000 --set-timestamp-to-revision repo

The packages are built in the container because the deltarpm library rejects
packages built by rpm 6.0.1, which no longer writes the legacy header tags it
requires. The delta rpms carry the header of the new package, so the tests read
them with the rpm package and compare it with the document. createrepo_c lists
the packages in hash order, which the writer keeps because it writes in the
order it is given.
