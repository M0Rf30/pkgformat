// Package apt is a client for Debian apt repositories that needs no apt
// installation: it refreshes package indexes, reads them, resolves
// dependencies and downloads packages with their integrity enforced.
//
// # Sources
//
// ParseSourcesList and ParseSources822 turn the text of sources.list and
// deb822 .sources files into Source values; LoadSources reads them from a file
// and a directory the caller names. The package never looks at /etc/apt on its
// own: every path is an option.
//
// # Updating
//
// Update fetches the Release of every source (InRelease, or Release with
// Release.gpg), verifies its signature with deb.Trust against the keyring named
// by the source's Signed-By option (a key file, a keyring directory entry, or
// an inline armored block) or UpdateOptions.DefaultKeyrings, and checks its
// dates the way apt does: Check-Valid-Until, Valid-Until-Min and
// Valid-Until-Max, Check-Date and Date-Max-Future. The Release is kept next to
// the indexes, so a later update refuses to replace a signed Release by an
// unsigned one (ErrDowngradeToInsecure) unless the source allows the
// downgrade, and Load can tell pins which suite an index came from.
//
// Every index the source asks for is then fetched, its size and SHA-256
// checked against the verified Release: Packages for each component and
// architecture, Translation files for the source's Languages (de_DE falls
// back to de), Contents when the Targets option names them, and Sources for a
// deb-src line. Flat repositories are supported. When the Release says
// Acquire-By-Hash the index is fetched from its by-hash path, with the plain
// path as the fallback (By-Hash=force makes by-hash the only one). When the
// lists directory already holds an older Packages file that the repository's
// Packages.diff knows, Update downloads the patches instead of the whole index
// if they are smaller than half of it, applies them and verifies the result
// against the Release; any failure falls back to the whole file. The indexes
// land in UpdateOptions.ListsDir under apt's own file names, so that apt
// itself can read them too.
//
// Sources may use http, https, file: and copy: URLs, and mirror+http,
// mirror+https and mirror+file: URLs whose document lists the mirrors to try
// in turn. A cdrom: source is reported as ErrUnsupportedScheme, as are other
// schemes. Trusted, Allow-Insecure, Allow-Weak, By-Hash, PDiffs, Languages,
// Targets, Architectures and the date options of a source are honoured as
// Source documents them. A signature that is present and wrong is always an
// error; a missing trust anchor, an unknown signer or an unsigned repository
// is accepted only with Trusted, Allow-Insecure or UpdateOptions.AllowUnverified.
//
// # Reading
//
// Load builds a Cache from a lists directory, and optionally a dpkg status
// file, whose path the caller gives. A Cache keeps every version of every
// package the indexes carry, per name and architecture, and the versions the
// status file says are installed. Lookup answers with the highest version,
// Versions with all of them.
//
// ResolveDeps works out what installing some packages would add, after apt's
// rules: version constraints (<<, <=, =, >=, >>) are honoured with
// deb.CompareVersions; alternatives are tried in order, an installed or
// already selected one first; a virtual package is met by its providers, a
// versioned dependency only by a versioned Provides; Pre-Depends count as
// Depends; a package that Conflicts with or Breaks an installed or selected
// one, or the other way round, is refused with a ConflictError; and
// Multi-Arch foreign, allowed and same decide which architecture meets a
// dependency, with "name:any", "name:native" and "name:arch" as apt reads
// them. An installed package whose version a dependency finds too old is
// upgraded if the indexes carry a newer one, else the dependency is
// unsatisfiable. The result is deterministic. Where it differs from apt (it
// never removes an installed package) is listed on ResolveDeps.
//
// # Pins and phased updates
//
// ParsePreferences and LoadPreferences read apt_preferences(5) files into
// Preferences; NewPolicy turns them, the release the user targets (apt -t) and
// the machine id into a Policy that gives every version its pin priority
// (Priority), selects the version to install (Candidate, or Cache.Candidate)
// and tells whether a phased update is withheld from a system (Phased). The
// rules are apt's: pins by release, version, source version and origin with
// fnmatch and regular expression patterns, NotAutomatic and
// ButAutomaticUpgrades, priority 100 for an installed-only version, and
// Phased-Update-Percentage decided by PhasedDraw, which reproduces apt's draw
// bit for bit.
//
// # Planning
//
// Cache.Plan predicts what apt-get would do to an installed system: the
// packages installed, upgraded, downgraded and removed, with the reason of
// each change, and the ones kept back. Installing a package that Conflicts with
// or Breaks an installed one removes or upgrades it, and what a change leaves
// broken is repaired the way apt's problem resolver repairs it. PlanRequest
// selects install and remove requests and the upgrade mode (upgrade,
// upgrade with new packages, dist-upgrade); PlanOptions carries the Policy and
// the held packages. The plans are checked against recorded apt-get -s output.
// Use ResolveDeps instead when nothing installed may be removed.
//
// # Downloading
//
// Cache.Download and Cache.DownloadClosure fetch .deb files into a directory.
// Each file is checked against the SHA-256 and size of the index while it is
// written, and a file that fails is not left behind. The result is a normal
// .deb for deb.ParseDebFileAt.
//
// A package whose base URL is a mirror list is fetched from the mirrors in
// turn; file: and copy: bases are copied, with the same checks.
//
// Transfers use the httpclient and download packages: size caps, retry with
// backoff, and a single retry over https when a plain http fetch fails
// transiently.
package apt
