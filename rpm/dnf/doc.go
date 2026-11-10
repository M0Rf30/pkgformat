// Package dnf is a client for dnf/yum repositories: it reads .repo files,
// refreshes repository metadata into a cache, indexes it, resolves package
// dependencies and downloads verified packages.
//
// It needs no dnf and no RPM database. Every host path is an option
// ([Options.RepoDir], [Options.CacheDir], [Options.VarsDir]), and what the host
// has installed is told by the program through [Installed].
//
// # Updating
//
// [Client.Update] fetches, for each enabled repository, repomd.xml and the
// primary (and module) metadata it names from one mirror, verifies the
// checksums, and only then commits them together with the mirror's URL. Mirrors
// are the baseurl entries in order or, without any, those of the mirror list or
// metalink (at most five); a mirror that fails or serves wrong bytes is
// replaced by the next. An unchanged repomd.xml is detected with a conditional
// request.
//
// # Resolving
//
// [Client.Load] builds an [Index] from the cached metadata. Packages of
// non-default module streams are left out, as dnf does without "module
// enable". [Index.Resolve] returns the packages to install in dependency order
// and the requirements nothing satisfies; dependencies are matched by name. Of
// several versions of a package the newest is chosen, by epoch, version and
// release ([Package.Compare]), after repository priority.
//
// # Downloading
//
// [Client.Download] and [Client.DownloadAll] write the .rpm files under their
// repository file name, after checking them against the SHA-256 (or SHA-512)
// of the metadata. A package without such a checksum is refused. With
// gpgcheck=1 the signature is checked as well (see below).
//
// # Repository settings
//
// Besides the URLs, a .repo file may set:
//
//   - gpgcheck=1 with gpgkey=: every package a [Client.Download] fetches must
//     carry a valid OpenPGP signature of one of the listed keys (http, https or
//     file URLs, variables expanded), checked with [rpm.VerifyWithOptions]
//     with signatures required. Revoked or expired keys, expired signatures,
//     unsigned packages and unknown signers fail, and so does gpgcheck=1
//     without a gpgkey ([ErrNoGPGKey]). gpgcheck=0, or none, checks nothing.
//   - exclude= or excludepkgs=: shell globs of package names (also of
//     name-version, name-version-release, name.arch and epoch forms) that are
//     left out of the index.
//   - priority=: the packages of a repository with a lower number replace
//     those of the same name from repositories with a higher one, whatever
//     the versions. The default is 99.
//   - proxy=, proxy_username=, proxy_password=: the proxy for every request of
//     the repository ("_none_" for none). It is applied to a copy of the
//     transport of [Options.HTTP], which must be an *http.Transport
//     ([ErrProxyUnsupported] otherwise).
//
// A mirror list that is a metalink also gives the size and hashes of
// repomd.xml: a mirror that serves anything else is skipped, and when no mirror
// serves the file the metalink names the update fails with
// [ErrMetalinkMismatch].
//
// Metadata and mirror lists come from the network and are not trusted: sizes
// are capped, locations are confined to the repository and the destination, and
// repository ids cannot leave the cache directory. Without a metalink the
// signature of repomd.xml (repo_gpgcheck) is not checked: the checksums protect
// against corrupted and mismatched mirrors, not against a repository that lies.
package dnf
