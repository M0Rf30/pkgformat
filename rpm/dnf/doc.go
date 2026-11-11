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
// [Client.Load] builds an [Index] from the cached metadata. It keeps every
// version and architecture of a package, drops those that exclude=,
// excludepkgs= and includepkgs= (of the repository and of [Config]) rule out
// and, as dnf does without "module enable", the packages of non-default
// module streams, except for repositories with module_hotfixes=1.
// [Index.Match] finds packages by name, name-version, name-version-release,
// name.arch or the epoch forms; of several matches the highest version of the
// best architecture comes first.
//
// [Index.Resolve] and [Index.ResolveWith] return the packages to install in
// dependency order. Requirements are matched with their versions against
// provides, files (looking in the file lists of the repositories, fetched only
// when a path needs them) and, for rich dependencies, evaluated with
// [richdep]. What the host has installed counts as satisfying a requirement
// when its version does, a newer package replaces an installed one (an
// upgrade) and Obsoletes remove installed packages. Conflicts and obsoletes
// rule packages out; a conflict nothing resolves is reported, not returned as
// an error. Of several providers the ones of the best repository priority are
// considered, then per name the best architecture (see [Config.MultilibPolicy]),
// the highest version and the lowest cost; among providers of different names,
// those named in the Recommends or Suggests of a package of the transaction
// or of the host come first, then the name asked for, a name that is
// installed, and the first in alphabetical order. Packages that were chosen for
// a requirement that another chosen package met too are dropped again.
//
// It is a greedy search, not libsolv's SAT solver. It resolves requirements
// that only one package can meet first and chooses among alternatives later,
// as libsolv does, and it checks the result against dnf on a trimmed snapshot of
// Fedora 43 (testdata/differential). The known differences are:
//
//   - It does not backtrack: a choice among alternatives that leads to a
//     conflict later is not revised, where dnf may find another way.
//   - The order in which alternatives are decided is not libsolv's, so the
//     provider chosen for a capability with several can differ.
//   - Weak dependencies are Recommends only, installed when
//     [ResolveOptions.WeakDeps] or install_weak_deps ask for them; Suggests,
//     Supplements and Enhances are not followed.
//   - installonlypkgs (several kernels at once), best=, skip_broken and
//     deltarpm are not supported. deltarpm= is read and ignored, as every
//     package is downloaded whole.
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
//   - proxy=, proxy_username=, proxy_password=, sslverify=, sslcacert=,
//     sslclientcert=, sslclientkey=, username=, password=: the proxy, TLS and
//     basic authentication of every request of the repository. They are
//     applied to a copy of the transport of [Options.HTTP], which must be an
//     *http.Transport ([ErrTransportUnsupported] otherwise); bad TLS files fail
//     with [ErrInvalidTLS].
//   - cost=: of several providers of equal priority the cheaper repository
//     wins. includepkgs=: only these packages are taken from the repository.
//   - module_hotfixes=1: the repository's packages ignore module filtering.
//   - skip_if_unavailable=1: a repository that cannot be fetched is skipped
//     rather than failing the update.
//   - metadata_expire=: how long cached metadata is fresh ([Client.Expired],
//     [Client.UpdateExpired]); 48h by default, "never" or -1 for no expiry.
//   - repo_gpgcheck=1: the detached signature of repomd.xml is fetched and
//     checked against the gpgkey keys before anything else is trusted
//     ([ErrRepoSignature]). localpkg_gpgcheck=1 makes [Client.VerifyLocal]
//     check local packages.
//   - countme=1: at most one request per week carries the countme flag of
//     the dnf protocol, with the age bucket of [Options.PersistDir].
//   - type=rpm-md and enabled_metadata= (filelists, other and updateinfo are
//     fetched in addition). Other repository types are refused.
//
// Values may use $releasever, $basearch, $arch, $releasever_major,
// $releasever_minor and the variables of the files in [Options.VarsDirs]. The
// [main] section of the dnf.conf at [Options.ConfigFile] gives the defaults
// ([Config], [Client.Config]).
//
// A mirror list that is a metalink also gives the size and hashes of
// repomd.xml: a mirror that serves anything else is skipped, and when no mirror
// serves the file the metalink names the update fails with
// [ErrMetalinkMismatch].
//
// Metadata and mirror lists come from the network and are not trusted: sizes
// are capped, locations are confined to the repository and the destination, and
// repository ids cannot leave the cache directory. Without a metalink or
// repo_gpgcheck=1 the signature of repomd.xml is not checked: the checksums
// protect against corrupted and mismatched mirrors, not against a repository
// that lies.
package dnf
