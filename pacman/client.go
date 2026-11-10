package pacman

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // repo-add publishes MD5 sums next to SHA-256; used only when no SHA-256 is given
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// Sizes the client enforces on what it downloads.
const (
	// DefaultMaxDBBytes bounds a downloaded database; the largest Arch ones are
	// well under 50 MiB.
	DefaultMaxDBBytes int64 = 256 << 20
	// DefaultMaxPackageBytes bounds a package whose database entry declares no
	// compressed size.
	DefaultMaxPackageBytes int64 = 16 << 30
	// DefaultSyncConcurrency is the number of repositories Sync refreshes at a
	// time.
	DefaultSyncConcurrency = 4
)

// Errors of the client. Test with errors.Is.
var (
	// ErrAllServersFailed wraps the failures of every server of a repository.
	ErrAllServersFailed = errors.New("pacman: all servers failed")
	// ErrNoServers reports a repository with no server.
	ErrNoServers = errors.New("pacman: repository has no servers")
	// ErrSignatureRequired reports a missing signature when the client is set
	// to require one.
	ErrSignatureRequired = errors.New("pacman: required signature is missing")
	// ErrNoKeyring reports a verification mode that needs a keyring, without one.
	ErrNoKeyring = errors.New("pacman: signature verification needs a keyring")
	// ErrChecksumMismatch reports a package that does not match the size or
	// digest its database entry declares.
	ErrChecksumMismatch = errors.New("pacman: package does not match its database entry")
	// ErrNoChecksum reports a database entry with neither a SHA-256 nor an MD5
	// sum, which makes the download unverifiable.
	ErrNoChecksum = errors.New("pacman: database entry has no checksum")
	// ErrInvalidRepoName reports a repository name that is not usable in a file
	// name.
	ErrInvalidRepoName = errors.New("pacman: invalid repository name")
)

// VerifyMode says how the client treats detached OpenPGP signatures.
type VerifyMode int

const (
	// VerifyNone never verifies. Databases still fetch their ".sig" on a
	// best-effort basis so it can be stored beside the database for other
	// tools.
	VerifyNone VerifyMode = iota
	// VerifyIfPresent verifies a signature the server provides and fails on an
	// invalid one; a server that has none (HTTP 404 or 410) is accepted.
	VerifyIfPresent
	// VerifyRequired fails when a signature is missing or invalid.
	VerifyRequired
)

// ClientOptions configures a Client. The zero value is valid: no
// verification, the default HTTP client and the architecture of the running
// system.
type ClientOptions struct {
	// HTTP fetches databases and signatures, with its retry policy and size
	// caps; packages are downloaded through it too. Nil builds a default client.
	HTTP *httpclient.Client
	// Arch replaces $arch in server URLs; empty selects ArchFromGOARCH of the
	// running system.
	Arch string
	// Keyring holds the public keys signatures are checked against.
	Keyring *gpg.Keyring
	// DBSignatures and PackageSignatures set the verification of databases
	// and of packages. Anything but VerifyNone needs Keyring.
	DBSignatures      VerifyMode
	PackageSignatures VerifyMode
	// MaxDBBytes bounds a database; zero selects DefaultMaxDBBytes.
	MaxDBBytes int64
	// Progress, when set, receives the progress of package downloads: the
	// file name, the bytes on disk and the expected total (-1 when unknown).
	// It may be called from several goroutines.
	Progress func(name string, done, total int64)
	// Logger receives one debug line per server tried. Nil is silent.
	Logger *slog.Logger
}

// Client fetches sync databases and packages from pacman mirrors. It is safe
// for concurrent use.
type Client struct {
	http *httpclient.Client
	opts ClientOptions
}

// NewClient returns a Client. It fails with ErrNoKeyring when a verification
// mode is set without a keyring.
func NewClient(opts ClientOptions) (*Client, error) {
	if (opts.DBSignatures != VerifyNone || opts.PackageSignatures != VerifyNone) && opts.Keyring.Len() == 0 {
		return nil, ErrNoKeyring
	}

	if opts.Arch == "" {
		opts.Arch = ArchFromGOARCH(runtime.GOARCH)
	}

	if opts.MaxDBBytes <= 0 {
		opts.MaxDBBytes = DefaultMaxDBBytes
	}

	h := opts.HTTP
	if h == nil {
		h = httpclient.New(httpclient.Options{})
	}

	return &Client{http: h, opts: opts}, nil
}

// DBFile is a downloaded sync database.
type DBFile struct {
	// Repo is the repository name.
	Repo string
	// URL is the address of the database that was fetched.
	URL string
	// Data is the compressed database as served.
	Data []byte
	// Sig is the binary detached signature, nil when the server has none.
	Sig []byte
	// Verified describes the signer when the signature was verified.
	Verified *gpg.Verified
}

// Entries parses the database.
func (d *DBFile) Entries() ([]DBEntry, error) {
	return ReadDB(bytes.NewReader(d.Data))
}

// ValidRepoName reports whether s can name a repository: it is used as a file
// name, so it must hold no path separator and not start with a dot.
func ValidRepoName(s string) bool {
	if s == "" || len(s) > MaxNameLen || s[0] == '.' {
		return false
	}

	for i := range len(s) {
		c := s[i]
		if c <= ' ' || c >= 0x7f || c == '/' || c == '\\' {
			return false
		}
	}

	return true
}

func (c *Client) base(server string, repo *Repo) string {
	return ExpandServer(server, repo.Name, c.opts.Arch)
}

func (c *Client) debug(msg string, args ...any) {
	if c.opts.Logger != nil {
		c.opts.Logger.Debug(msg, args...)
	}
}

// FetchDB downloads the database of repo from the first server that serves it
// (and, per the verification mode, a valid signature for it).
func (c *Client) FetchDB(ctx context.Context, repo Repo) (*DBFile, error) {
	if !ValidRepoName(repo.Name) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidRepoName, repo.Name)
	}

	if len(repo.Servers) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoServers, repo.Name)
	}

	var errs []error

	for _, server := range repo.Servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		db, err := c.fetchDBFrom(ctx, c.base(server, &repo)+"/"+repo.Name+".db", repo.Name)
		if err == nil {
			return db, nil
		}

		c.debug("pacman: server failed", "repo", repo.Name, "server", server, "error", err)

		errs = append(errs, err)
	}

	return nil, fmt.Errorf("%w for %q: %w", ErrAllServersFailed, repo.Name, errors.Join(errs...))
}

func (c *Client) fetchDBFrom(ctx context.Context, url, repo string) (*DBFile, error) {
	data, err := c.http.FetchBytes(ctx, url, c.opts.MaxDBBytes)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}

	db := &DBFile{Repo: repo, URL: url, Data: data}

	sig, err := c.http.FetchBytes(ctx, url+".sig", MaxSignatureBytes)

	switch {
	case err == nil:
		db.Sig = sig
	case c.opts.DBSignatures == VerifyNone || isAbsent(err):
		// No signature, or none usable and none demanded.
	default:
		return nil, fmt.Errorf("fetching %s.sig: %w", url, err)
	}

	if c.opts.DBSignatures != VerifyNone {
		v, err := c.verify(bytes.NewReader(data), db.Sig, c.opts.DBSignatures)
		if err != nil {
			return nil, fmt.Errorf("verifying %s: %w", url, err)
		}

		db.Verified = v
	}

	return db, nil
}

// isAbsent reports a server answer that says the file does not exist.
func isAbsent(err error) bool {
	var st *httpclient.HTTPStatusError

	return errors.As(err, &st) && (st.Code == http.StatusNotFound || st.Code == http.StatusGone)
}

// verify checks sig over data. A nil sig is acceptable except in
// VerifyRequired mode; it returns nil, nil then.
func (c *Client) verify(data io.Reader, sig []byte, mode VerifyMode) (*gpg.Verified, error) {
	if len(sig) == 0 {
		if mode == VerifyRequired {
			return nil, ErrSignatureRequired
		}

		return nil, nil //nolint:nilnil // an absent, optional signature has nothing to report
	}

	v, err := gpg.VerifyDetached(c.opts.Keyring, data, sig)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// SyncDB downloads the database of repo into dir as "<repo>.db", with its
// signature as "<repo>.db.sig"; a stale signature from an earlier sync is
// removed when the server has none, since it would not match the new database.
// Both files are replaced atomically.
func (c *Client) SyncDB(ctx context.Context, repo Repo, dir string) (*DBFile, error) {
	db, err := c.FetchDB(ctx, repo)
	if err != nil {
		return nil, err
	}

	dest := filepath.Join(dir, repo.Name+".db")

	if err := httpclient.AtomicWrite(dest, func(w io.Writer) error {
		_, err := w.Write(db.Data)

		return err
	}); err != nil {
		return nil, fmt.Errorf("pacman: writing %s: %w", dest, err)
	}

	sigDest := dest + ".sig"

	if len(db.Sig) == 0 {
		if err := os.Remove(sigDest); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pacman: removing stale %s: %w", sigDest, err)
		}

		return db, nil
	}

	if err := httpclient.AtomicWrite(sigDest, func(w io.Writer) error {
		_, err := w.Write(db.Sig)

		return err
	}); err != nil {
		return nil, fmt.Errorf("pacman: writing %s: %w", sigDest, err)
	}

	return db, nil
}

// Sync refreshes the databases of repos into dir, up to DefaultSyncConcurrency
// at a time. A repository that fails does not stop the others: it returns how
// many succeeded and the joined failures (each wrapping its repository name's
// ErrAllServersFailed or the cause).
func (c *Client) Sync(ctx context.Context, repos []Repo, dir string) (int, error) {
	var (
		mu        sync.Mutex
		succeeded int
		errs      = make([]error, len(repos))
	)

	var g errgroup.Group

	g.SetLimit(DefaultSyncConcurrency)

	for i := range repos {
		g.Go(func() error {
			_, errs[i] = c.SyncDB(ctx, repos[i], dir)

			if errs[i] == nil {
				mu.Lock()

				succeeded++

				mu.Unlock()
			}

			return nil
		})
	}

	_ = g.Wait()

	return succeeded, errors.Join(errs...)
}

// DownloadPackage downloads the package described by entry from the servers of
// repo into dir and returns its path. The file is checked against the size and
// SHA-256 (or, failing that, MD5) of the entry and, per the verification
// mode, against its signature: the one the entry carries, else "<file>.sig"
// from the server. A package already in dir that passes the checks is reused.
// Servers are tried in order; a package that fails a check is discarded and the
// next server is tried.
func (c *Client) DownloadPackage(ctx context.Context, repo Repo, entry *DBEntry, dir string) (string, error) {
	if !ValidFileName(entry.Filename) {
		return "", fmt.Errorf("%w: file name %q", ErrInvalidField, entry.Filename)
	}

	if !ValidRepoName(repo.Name) {
		return "", fmt.Errorf("%w: %q", ErrInvalidRepoName, repo.Name)
	}

	if len(repo.Servers) == 0 {
		return "", fmt.Errorf("%w: %s", ErrNoServers, repo.Name)
	}

	sum, err := entryChecksum(entry)
	if err != nil {
		return "", err
	}

	dest := filepath.Join(dir, entry.Filename)

	if _, statErr := os.Stat(dest); statErr == nil {
		if cerr := c.checkPackage(ctx, "", dest, entry, sum, true); cerr == nil {
			return dest, nil
		}

		_ = os.Remove(dest)
	}

	var errs []error

	for _, server := range repo.Servers {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		url := c.base(server, &repo) + "/" + entry.Filename

		err := c.downloadFrom(ctx, url, dest, entry, sum)
		if err == nil {
			return dest, nil
		}

		c.debug("pacman: server failed", "repo", repo.Name, "url", url, "error", err)

		errs = append(errs, err)
	}

	return "", fmt.Errorf("%w for %q: %w", ErrAllServersFailed, entry.Filename, errors.Join(errs...))
}

type checksum struct {
	req *download.Checksum
}

func entryChecksum(e *DBEntry) (*checksum, error) {
	switch {
	case e.SHA256 != "":
		sum, err := download.ParseChecksum("sha256", e.SHA256)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidField, err)
		}

		return &checksum{req: sum}, nil
	case e.MD5 != "":
		sum, err := download.ParseChecksum("md5", e.MD5)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidField, err)
		}

		return &checksum{req: sum}, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrNoChecksum, e.Filename)
}

func (c *Client) downloadFrom(ctx context.Context, url, dest string, entry *DBEntry, sum *checksum) error {
	limit := entry.CSize
	if limit <= 0 {
		limit = DefaultMaxPackageBytes
	}

	req := download.Request{URL: url, Dest: dest, Checksum: sum.req, MaxBytes: limit}

	if c.opts.Progress != nil {
		name := entry.Filename
		req.Progress = func(done, total int64) { c.opts.Progress(name, done, total) }
	}

	if err := download.Download(ctx, req, download.Options{Client: c.http}); err != nil {
		if errors.Is(err, download.ErrChecksumMismatch) {
			return fmt.Errorf("%w: %s: %w", ErrChecksumMismatch, url, err)
		}

		return fmt.Errorf("downloading %s: %w", url, err)
	}

	if err := c.checkPackage(ctx, url, dest, entry, sum, false); err != nil {
		_ = os.Remove(dest)

		return err
	}

	return nil
}

// checkPackage verifies the file at path against the entry: its size, its
// digest when checkDigest is set (the downloader has already checked it
// otherwise) and, per the verification mode, its signature. url is where a
// missing signature is fetched from; empty means the file came from the cache
// and its signature can only come from the entry.
func (c *Client) checkPackage(
	ctx context.Context, url, path string, entry *DBEntry, sum *checksum, checkDigest bool,
) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	if entry.CSize > 0 && fi.Size() != entry.CSize {
		return fmt.Errorf("%w: %s is %d bytes, the database says %d",
			ErrChecksumMismatch, entry.Filename, fi.Size(), entry.CSize)
	}

	if checkDigest {
		h := sum.req.New()

		if _, err := io.Copy(h, f); err != nil {
			return err
		}

		if !bytes.Equal(h.Sum(nil), sum.req.Sum) {
			return fmt.Errorf("%w: digest of %s", ErrChecksumMismatch, entry.Filename)
		}

		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}

	mode := c.opts.PackageSignatures
	if mode == VerifyNone {
		return nil
	}

	sig, err := c.packageSignature(ctx, url, entry, mode)
	if err != nil {
		return err
	}

	if _, err := c.verify(f, sig, mode); err != nil {
		return fmt.Errorf("verifying %s: %w", entry.Filename, err)
	}

	return nil
}

// packageSignature returns the signature of a package: the base64 one of the
// database entry, else the ".sig" file next to the package on the server.
func (c *Client) packageSignature(ctx context.Context, url string, entry *DBEntry, mode VerifyMode) ([]byte, error) {
	if entry.PGPSig != "" {
		sig, err := base64.StdEncoding.DecodeString(entry.PGPSig)
		if err != nil {
			return nil, fmt.Errorf("%w: PGPSIG of %s: %w", ErrInvalidField, entry.Filename, err)
		}

		return sig, nil
	}

	if url == "" {
		return nil, nil
	}

	sig, err := c.http.FetchBytes(ctx, url+".sig", MaxSignatureBytes)
	if err != nil {
		if isAbsent(err) && mode != VerifyRequired {
			return nil, nil
		}

		if isAbsent(err) {
			return nil, ErrSignatureRequired
		}

		return nil, fmt.Errorf("fetching %s.sig: %w", url, err)
	}

	return sig, nil
}

// FileSums returns the MD5 and SHA-256 of data as hex, the sums a database
// entry carries.
func FileSums(data io.Reader) (md5sum, sha256sum string, err error) {
	m, s := md5.New(), sha256.New() //nolint:gosec // MD5 is part of the database format

	if _, err := io.Copy(io.MultiWriter(m, s), data); err != nil {
		return "", "", fmt.Errorf("pacman: hashing: %w", err)
	}

	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), nil
}

// NewDBEntry builds the database entry of a package file read from r: the
// file's .PKGINFO and file list, its compressed size and its sums, as repo-add
// records them. sig, when not empty, is the binary detached signature of the
// file. Entries are meant for WriteDB.
func NewDBEntry(filename string, pkgFile io.ReadSeeker, sig []byte) (*DBEntry, error) {
	size, err := pkgFile.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("pacman: sizing %s: %w", filename, err)
	}

	if _, err := pkgFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("pacman: reading %s: %w", filename, err)
	}

	md5sum, sha256sum, err := FileSums(pkgFile)
	if err != nil {
		return nil, err
	}

	if _, err := pkgFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("pacman: reading %s: %w", filename, err)
	}

	pkg, err := ReadPackage(pkgFile)
	if err != nil {
		return nil, err
	}

	if !ValidFileName(filename) {
		return nil, fmt.Errorf("%w: file name %q", ErrInvalidField, filename)
	}

	i := pkg.Info

	e := &DBEntry{
		Filename: filename, Name: i.Name, Base: i.Base, Version: i.Version, Description: i.Description,
		Groups: i.Groups, CSize: size, ISize: i.InstalledSz, MD5: md5sum, SHA256: sha256sum,
		URL: i.URL, Licenses: i.Licenses, Arch: i.Arch, BuildDate: i.BuildDate, Packager: i.Packager,
		Replaces: i.Replaces, Conflicts: i.Conflicts, Provides: i.Provides, Depends: i.Depends,
		OptDepends: i.OptDepends, MakeDepends: i.MakeDepends, CheckDepends: i.CheckDepends, Files: pkg.Files,
	}

	if len(sig) > 0 {
		bin, err := NormalizeSignature(sig)
		if err != nil {
			return nil, err
		}

		e.PGPSig = base64.StdEncoding.EncodeToString(bin)
	}

	return e, nil
}
