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
// by the source's Signed-By option or UpdateOptions.DefaultKeyrings, rejects an
// expired Release, then downloads the Packages index of each component and
// architecture, checking its size and SHA-256 against the verified Release.
// The indexes land in UpdateOptions.ListsDir under apt's own file names, so
// that apt itself can read them too. A signature that is present and wrong is
// always an error; a missing trust anchor, an unknown signer or an unsigned
// repository is accepted only with UpdateOptions.AllowUnverified.
//
// # Reading
//
// Load builds a Cache from a lists directory, and optionally a dpkg status
// file, whose path the caller gives. A Cache answers Lookup, ResolveVirtual
// and ResolveDeps, with Multi-Arch awareness: Multi-Arch: foreign packages are
// redirected to the host architecture and architecture-qualified names are
// inherited by dependencies. The highest Debian version wins when several
// repositories carry one package.
//
// # Downloading
//
// Cache.Download and Cache.DownloadClosure fetch .deb files into a directory.
// Each file is checked against the SHA-256 and size of the index while it is
// written, and a file that fails is not left behind. The result is a normal
// .deb for deb.ParseDebFileAt.
//
// Transfers use the httpclient and download packages: size caps, retry with
// backoff, and a single retry over https when a plain http fetch fails
// transiently.
package apt
