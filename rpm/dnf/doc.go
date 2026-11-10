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
// and the requirements nothing satisfies; dependencies are matched by name.
//
// # Downloading
//
// [Client.Download] and [Client.DownloadAll] write the .rpm files under their
// repository file name, after checking them against the SHA-256 (or SHA-512)
// of the metadata. A package without such a checksum is refused.
//
// Metadata and mirror lists come from the network and are not trusted: sizes
// are capped, locations are confined to the repository and the destination, and
// repository ids cannot leave the cache directory. Signatures of repomd.xml
// are not checked; the checksums protect against corrupted and mismatched
// mirrors, not against a repository that lies.
package dnf
