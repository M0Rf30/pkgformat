package deb

import (
	"bytes"
	"crypto/md5"  //nolint:gosec // the dpkg-sig manifest format lists MD5 digests
	"crypto/sha1" //nolint:gosec // the dpkg-sig manifest format lists SHA-1 digests
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/gpg"
)

// Sentinel errors of package signing. Test with errors.Is.
var (
	// ErrNoPackageSignature is returned by VerifySignatures for a package that
	// carries no signature member.
	ErrNoPackageSignature = errors.New("deb: package carries no signature")
	// ErrInvalidPackageSignature is returned when a signature member does not
	// match the package or is malformed. The cause stays in the chain.
	ErrInvalidPackageSignature = errors.New("deb: invalid package signature")
	// ErrSignatureExists is returned when the package already holds a
	// signature member of the requested name.
	ErrSignatureExists = errors.New("deb: package already carries this signature")
	// ErrInvalidSignRole is returned for a signing role that cannot form a
	// member name.
	ErrInvalidSignRole = errors.New("deb: invalid signing role")
)

// SignScheme selects the layout of a package signature.
type SignScheme int

const (
	// SchemeDebsigs is the debsigs layout, checked by debsig-verify: a binary
	// or armored detached signature, in the member "_gpg" + role, over the
	// concatenation of the content of debian-binary, the control archive and the
	// data archive.
	SchemeDebsigs SignScheme = iota
	// SchemeDpkgSig is the dpkg-sig layout: a clear-signed manifest listing the
	// size, MD5 and SHA-1 of the members, in the member "_gpg" + role.
	SchemeDpkgSig
)

// String returns the scheme name.
func (s SignScheme) String() string {
	if s == SchemeDpkgSig {
		return "dpkg-sig"
	}

	return "debsigs"
}

const (
	sigMemberPrefix = "_gpg"
	// dpkgSigVersion is the manifest version dpkg-sig writes and understands.
	dpkgSigVersion = 4
	// arNameMax is the longest member name an ar header holds.
	arNameMax = arNameLen
	// debsigsRoleOrigin is the role debsig-verify checks policies of type
	// "origin" against.
	debsigsRoleOrigin = "origin"
	dpkgSigRoleBuild  = "builder"
)

// SignOptions tunes SignPackage. The zero value signs with the debsigs scheme
// and the default role of that scheme.
type SignOptions struct {
	// Scheme selects the signature layout.
	Scheme SignScheme
	// Role is the signing role: "origin" (default), "maint" or "archive" for
	// debsigs, and "builder" (default), "uploader", "maint" ... for dpkg-sig.
	// It becomes the member name "_gpg" + Role.
	Role string
	// Signer is the identity recorded in a dpkg-sig manifest. Empty means the
	// key fingerprint.
	Signer string
	// Time is the date recorded in the member header and in a dpkg-sig
	// manifest. Zero means time.Now().
	Time time.Time
}

func (o SignOptions) role() string {
	if o.Role != "" {
		return o.Role
	}

	if o.Scheme == SchemeDpkgSig {
		return dpkgSigRoleBuild
	}

	return debsigsRoleOrigin
}

func (o SignOptions) validate() error {
	r := o.role()

	if len(sigMemberPrefix)+len(r) > arNameMax {
		return fmt.Errorf("%w: %q makes a member name longer than %d bytes", ErrInvalidSignRole, r, arNameMax)
	}

	for _, c := range r {
		if c < 'a' || c > 'z' {
			return fmt.Errorf("%w: %q, want lower-case letters", ErrInvalidSignRole, r)
		}
	}

	if o.Scheme != SchemeDebsigs && o.Scheme != SchemeDpkgSig {
		return fmt.Errorf("%w: unknown scheme %d", ErrInvalidSignRole, o.Scheme)
	}

	return nil
}

// corePackageMembers returns the debian-binary, control and data members of an
// ar archive, in the order a signature covers them.
func corePackageMembers(members []arMember) (core [3]*arMember, err error) {
	for i := range members {
		m := &members[i]

		switch {
		case m.Name == "debian-binary" && core[0] == nil:
			core[0] = m
		case strings.HasPrefix(m.Name, controlTarName) && core[1] == nil:
			core[1] = m
		case strings.HasPrefix(m.Name, dataTarName) && core[2] == nil:
			core[2] = m
		}
	}

	switch {
	case core[0] == nil:
		return core, fmt.Errorf("%w: no debian-binary member", ErrInvalidPackage)
	case core[1] == nil:
		return core, fmt.Errorf("%w: %w", ErrInvalidPackage, ErrControlArchiveNotFound)
	case core[2] == nil:
		return core, fmt.Errorf("%w: %w", ErrInvalidPackage, ErrDataArchiveNotFound)
	}

	return core, nil
}

func memberReader(r io.ReaderAt, m *arMember) io.Reader {
	return io.NewSectionReader(r, m.dataOff, m.Size)
}

// SignPackage copies the package read from r (size bytes) to w and appends a
// signature member made with signer, in the layout opts selects. Signatures the
// package already carries are kept; signing the same package again under the
// same role fails with ErrSignatureExists, except for dpkg-sig where the member
// name gets the suffix 0-9, A-Z that dpkg-sig itself picks. Every failure to
// read the package wraps ErrInvalidPackage.
func SignPackage(w io.Writer, r io.ReaderAt, size int64, signer gpg.Signer, opts SignOptions) error {
	if signer == nil {
		return ErrNoSigner
	}

	if err := opts.validate(); err != nil {
		return err
	}

	members, err := readARMembers(r, size)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPackage, err)
	}

	core, err := corePackageMembers(members)
	if err != nil {
		return err
	}

	name, err := signatureMemberName(members, opts)
	if err != nil {
		return err
	}

	now := opts.Time
	if now.IsZero() {
		now = time.Now()
	}

	var body []byte

	switch opts.Scheme {
	case SchemeDpkgSig:
		body, err = dpkgSigBody(signer, r, core, opts, now)
	default:
		body, err = signer.DetachedSign(io.MultiReader(
			memberReader(r, core[0]), memberReader(r, core[1]), memberReader(r, core[2])))
		if err != nil {
			err = fmt.Errorf("deb: signing package: %w", err)
		}
	}

	if err != nil {
		return err
	}

	if _, err := io.Copy(w, io.NewSectionReader(r, 0, size)); err != nil {
		return fmt.Errorf("deb: copying package: %w", err)
	}

	// A well-formed archive pads odd members; tolerate one that does not.
	if size%arMemberAlign != 0 {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return fmt.Errorf("deb: copying package: %w", err)
		}
	}

	aw := &arWriter{w: w}

	return aw.member(name, int64(len(body)), now, bytes.NewReader(body))
}

func signatureMemberName(members []arMember, opts SignOptions) (string, error) {
	base := sigMemberPrefix + opts.role()

	taken := func(n string) bool {
		for i := range members {
			if members[i].Name == n {
				return true
			}
		}

		return false
	}

	if !taken(base) {
		return base, nil
	}

	if opts.Scheme == SchemeDpkgSig && len(base) < arNameMax {
		for _, c := range "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
			if n := base + string(c); !taken(n) {
				return n, nil
			}
		}
	}

	return "", fmt.Errorf("%w: %s", ErrSignatureExists, base)
}

// memberDigest is the size and digests of one ar member, as a dpkg-sig
// manifest lists them.
type memberDigest struct {
	name string
	size int64
	md5  string
	sha1 string
}

func digestMember(r io.ReaderAt, m *arMember) (memberDigest, error) {
	hm, hs := md5.New(), sha1.New() //nolint:gosec // see the imports

	n, err := io.Copy(io.MultiWriter(hm, hs), memberReader(r, m))
	if err != nil {
		return memberDigest{}, fmt.Errorf("reading %s: %w", m.Name, err)
	}

	return memberDigest{
		name: m.Name, size: n,
		md5: hex.EncodeToString(hm.Sum(nil)), sha1: hex.EncodeToString(hs.Sum(nil)),
	}, nil
}

// dpkgSigTime formats a date the way perl's localtime does in dpkg-sig, e.g.
// "Wed Nov 11 00:40:03 2026".
func dpkgSigTime(t time.Time) string {
	return t.Format("Mon Jan _2 15:04:05 2006")
}

func dpkgSigBody(signer gpg.Signer, r io.ReaderAt, core [3]*arMember, opts SignOptions, now time.Time) ([]byte, error) {
	who := opts.Signer
	if who == "" {
		who = signer.KeyFingerprint()
	}

	if strings.ContainsAny(who, "\r\n") {
		return nil, fmt.Errorf("%w: signer %q holds a line break", ErrInvalidSpec, who)
	}

	var b strings.Builder

	fmt.Fprintf(&b, "Version: %d\nSigner: %s\nDate: %s\nRole: %s\nFiles: \n",
		dpkgSigVersion, who, dpkgSigTime(now.Local()), opts.role())

	for _, m := range core {
		d, err := digestMember(r, m)
		if err != nil {
			return nil, err
		}

		fmt.Fprintf(&b, "\t%s %s %d %s\n", d.md5, d.sha1, d.size, d.name)
	}

	signed, err := signer.CleartextSign(strings.NewReader(b.String()))
	if err != nil {
		return nil, fmt.Errorf("deb: signing package: %w", err)
	}

	out, err := io.ReadAll(signed)
	if err != nil {
		return nil, fmt.Errorf("deb: signing package: %w", err)
	}

	return out, nil
}

// PackageSignature is the outcome of checking one signature member.
type PackageSignature struct {
	// Member is the ar member name, such as "_gpgorigin".
	Member string
	// Scheme is the layout the member was read as.
	Scheme SignScheme
	// Role is the role the member name carries ("origin", "builder", ...).
	Role string
	// Signer describes the key that made a valid signature.
	Signer gpg.Verified
	// Err is nil for a valid signature, else the reason it is not, wrapping
	// ErrInvalidPackageSignature or, for a key outside the keyring,
	// gpg.ErrUnknownSigner.
	Err error
}

// VerifySignatures checks every signature member of the package against kr and
// returns one result per member, in archive order. The error is
// ErrNoPackageSignature for an unsigned package, and a join of the failures of
// the members that do not verify; the results are returned in both cases.
//
// A member that holds a clear-signed manifest is read as dpkg-sig's, any other
// as debsigs'. A debsigs signature covers the three core members; a dpkg-sig
// one covers the members its manifest lists, which must include
// debian-binary, the control archive and the data archive.
func (d *DebFile) VerifySignatures(kr *gpg.Keyring) ([]PackageSignature, error) {
	if len(d.Signatures) == 0 {
		return nil, ErrNoPackageSignature
	}

	core, err := corePackageMembers(d.members)
	if err != nil {
		return nil, err
	}

	var (
		results []PackageSignature
		errs    []error
	)

	for _, s := range d.Signatures {
		res := PackageSignature{Member: s.Name, Role: roleOfMember(s.Name)}

		if bytes.Contains(s.Data[:min(len(s.Data), 128)], []byte("BEGIN PGP SIGNED MESSAGE")) {
			res.Scheme = SchemeDpkgSig
			res.Signer, res.Err = d.verifyDpkgSig(kr, s, res.Role)
		} else {
			res.Scheme = SchemeDebsigs
			res.Signer, res.Err = gpg.VerifyDetached(kr, io.MultiReader(
				memberReader(d.r, core[0]), memberReader(d.r, core[1]), memberReader(d.r, core[2])), s.Data)
		}

		if res.Err != nil {
			res.Err = invalidSignature(s.Name, res.Err)
			errs = append(errs, res.Err)
		}

		results = append(results, res)
	}

	return results, errors.Join(errs...)
}

// invalidSignature wraps err so that it matches ErrInvalidPackageSignature
// unless it already does.
func invalidSignature(member string, err error) error {
	if errors.Is(err, ErrInvalidPackageSignature) {
		return err
	}

	return fmt.Errorf("%w: %s: %w", ErrInvalidPackageSignature, member, err)
}

// roleOfMember extracts the role of a signature member name: "_gpgbuilder",
// "_gpgbuilder1" -> "builder".
func roleOfMember(name string) string {
	role := strings.TrimPrefix(name, sigMemberPrefix)
	if n := len(role); n > 1 {
		if c := role[n-1]; c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' {
			role = role[:n-1]
		}
	}

	return role
}

func (d *DebFile) verifyDpkgSig(kr *gpg.Keyring, s SignatureMember, role string) (gpg.Verified, error) {
	body, who, err := gpg.VerifyClearsigned(kr, s.Data)
	if err != nil {
		return gpg.Verified{}, err
	}

	fields, files := parseDpkgSigManifest(string(body))

	version, err := strconv.Atoi(fields["version"])
	if err != nil || version < 1 {
		return gpg.Verified{}, fmt.Errorf("%w: manifest version %q", ErrInvalidPackageSignature, fields["version"])
	}

	if version > dpkgSigVersion {
		return gpg.Verified{}, fmt.Errorf("%w: manifest version %d is newer than %d",
			ErrInvalidPackageSignature, version, dpkgSigVersion)
	}

	if fields["role"] != role {
		return gpg.Verified{}, fmt.Errorf("%w: member name says role %q, manifest %q",
			ErrInvalidPackageSignature, role, fields["role"])
	}

	seen := make(map[string]bool, len(files))

	for _, f := range files {
		m := d.findMember(f.name)
		if m == nil {
			return gpg.Verified{}, fmt.Errorf("%w: %s is signed but not in the package",
				ErrInvalidPackageSignature, f.name)
		}

		got, err := digestMember(d.r, m)
		if err != nil {
			return gpg.Verified{}, err
		}

		if got.size != f.size || got.sha1 != f.sha1 || got.md5 != f.md5 {
			return gpg.Verified{}, fmt.Errorf("%w: %s differs from the signed digests",
				ErrInvalidPackageSignature, f.name)
		}

		seen[f.name] = true
	}

	if err := requireCoreSigned(seen); err != nil {
		return gpg.Verified{}, err
	}

	return who, nil
}

func requireCoreSigned(seen map[string]bool) error {
	has := func(prefix string) bool {
		for n := range seen {
			if n == prefix || strings.HasPrefix(n, prefix+".") {
				return true
			}
		}

		return false
	}

	if !seen["debian-binary"] || !has(controlTarName) || !has(dataTarName) {
		return fmt.Errorf("%w: the manifest must list debian-binary, the control archive and the data archive",
			ErrInvalidPackageSignature)
	}

	return nil
}

func (d *DebFile) findMember(name string) *arMember {
	for i := range d.members {
		if d.members[i].Name == name {
			return &d.members[i]
		}
	}

	return nil
}

// parseDpkgSigManifest reads the RFC 822-like body of a dpkg-sig signature.
// Field names are lower-cased; the Files continuation lines are parsed into
// digests, malformed ones skipped.
func parseDpkgSigManifest(body string) (map[string]string, []memberDigest) {
	fields := make(map[string]string)

	var (
		files []memberDigest
		cur   string
	)

	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimRight(line, "\r")

		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			if cur != "files" {
				continue
			}

			f := strings.Fields(line)
			if len(f) != 4 {
				continue
			}

			size, err := strconv.ParseInt(f[2], 10, 64)
			if err != nil {
				continue
			}

			files = append(files, memberDigest{name: f[3], size: size, md5: f[0], sha1: f[1]})

			continue
		}

		if k, v, ok := strings.Cut(line, ":"); ok {
			cur = strings.ToLower(strings.TrimSpace(k))
			fields[cur] = strings.TrimSpace(v)
		}
	}

	return fields, files
}
