package rpm

import (
	"crypto/md5"  //nolint:gosec // G501: FILEDIGESTS of old packages are MD5
	"crypto/sha1" //nolint:gosec // G505: FILEDIGESTS of some old packages are SHA-1
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"os/user"
	"strconv"

	"github.com/M0Rf30/pkgformat/rpm/cpio"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// ErrDigestMismatch is matched (errors.Is) by the error ExpandPayload returns
// when the contents of a file do not match the digest in the package header.
// The error is a [*DigestMismatchError].
var ErrDigestMismatch = cpio.ErrDigestMismatch

// DigestMismatchError describes the file whose contents do not match the
// digest in the package header.
type DigestMismatchError = cpio.DigestMismatchError

// ExpandOptions tunes [Rpm.ExpandPayloadWithOptions]. The zero value extracts
// like [Rpm.ExpandPayload].
type ExpandOptions struct {
	// Umask clears the given bits of every file and directory mode, as a
	// unix mask over the permission bits (0777) and the special bits: 07000
	// drops set-uid, set-gid and sticky. The default applies the modes of
	// the package unchanged, as rpm does.
	Umask uint32

	// Chown applies the file owners (FILEUSERNAME/FILEGROUPNAME) of the
	// package. Names are resolved with LookupUser and LookupGroup; a file
	// whose owner cannot be resolved keeps the extracting user. Ignored, with a
	// warning, unless the process runs as root.
	Chown bool

	// LookupUser and LookupGroup map an owner name to a numeric id for Chown.
	// They default to the host's user database ([os/user]).
	LookupUser  func(name string) (int, error)
	LookupGroup func(name string) (int, error)

	// SpecialFiles allows creating device nodes, FIFOs and sockets. They are
	// skipped, with a logged warning, unless set. Devices need privileges.
	SpecialFiles bool

	// SkipDigests disables the verification of regular file contents against
	// FILEDIGESTS. By default a mismatch fails the extraction with a
	// [*DigestMismatchError].
	SkipDigests bool

	// Logger receives a warning for everything that is skipped. Nil discards.
	Logger *slog.Logger
}

// ExpandPayload extracts the payload of a RPM to the specified directory.
// It is [Rpm.ExpandPayloadWithOptions] with the default options: modes
// (including set-uid, set-gid and sticky bits) and modification times are
// applied as recorded, contents are checked against FILEDIGESTS, owners are
// not applied and device nodes, FIFOs and sockets are skipped. Both cpio
// payloads of RPM v3/v4 and the stripped payloads of RPM v6 are handled.
func (rpm *Rpm) ExpandPayload(dest string) error {
	return rpm.ExpandPayloadWithOptions(dest, nil)
}

// ExpandPayloadWithOptions extracts the payload of a RPM to dest as
// configured by opts (nil means defaults). Files in dest are confined as
// described in [cpio.ExtractWithOptions]; files flagged %ghost are not part of
// the payload and are not created.
func (rpm *Rpm) ExpandPayloadWithOptions(dest string, opts *ExpandOptions) error {
	var o ExpandOptions
	if opts != nil {
		o = *opts
	}
	files, err := rpm.Header.GetFiles()
	if err != nil {
		return err
	}
	co := &cpio.ExtractOptions{
		Umask:        o.Umask,
		Chown:        o.Chown,
		SpecialFiles: o.SpecialFiles,
		Logger:       o.Logger,
	}
	if !o.SkipDigests {
		if co.NewDigest, err = rpm.fileDigest(); err != nil {
			return err
		}
	}
	co.Files = o.fileMetas(files, o.Chown && os.Geteuid() == 0)

	pld, err := rpm.uncompressedPayload()
	if err != nil {
		return err
	}
	if c, ok := pld.(io.Closer); ok {
		defer c.Close()
	}
	return cpio.ExtractWithOptions(pld, dest, co)
}

// fileMetas converts the header file list to what the cpio extractor needs.
func (o *ExpandOptions) fileMetas(files []FileInfo, resolveOwners bool) []cpio.FileMeta {
	sizes, nlinks, _ := payloadLayout(files)
	metas := make([]cpio.FileMeta, len(files))
	users := map[string]int{}
	groups := map[string]int{}
	lookup := func(cache map[string]int, name string, fn func(string) (int, error)) int {
		if id, ok := cache[name]; ok {
			return id
		}
		id, err := fn(name)
		if err != nil {
			id = -1
			if o.Logger != nil {
				o.Logger.Warn("cannot resolve file owner", "name", name, "error", err)
			}
		}
		cache[name] = id
		return id
	}
	lookupUser, lookupGroup := o.LookupUser, o.LookupGroup
	if lookupUser == nil {
		lookupUser = func(n string) (int, error) {
			u, err := user.Lookup(n)
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(u.Uid)
		}
	}
	if lookupGroup == nil {
		lookupGroup = func(n string) (int, error) {
			g, err := user.LookupGroup(n)
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(g.Gid)
		}
	}
	for i, f := range files {
		fi := f.(*fileInfo)
		m := cpio.FileMeta{
			Name:  fi.name,
			Mode:  fi.mode,
			Size:  sizes[i],
			UID:   -1,
			GID:   -1,
			Mtime: int64(fi.mtime),
			Rdev:  uint64(fi.rdev),
			Nlink: nlinks[i],
		}
		if nlinks[i] > 1 {
			m.Inode = fi.inode64()
		}
		if fi.fileType() == cpio.S_ISREG && fi.flags&tag.RPMFILE_GHOST == 0 {
			m.Digest = fi.digest
		}
		if resolveOwners {
			m.UID = lookup(users, fi.userName, lookupUser)
			m.GID = lookup(groups, fi.groupName, lookupGroup)
		}
		metas[i] = m
	}
	return metas
}

// fileDigest returns the constructor of the hash named by FILEDIGESTALGO.
// Packages without the tag use MD5.
func (rpm *Rpm) fileDigest() (func() hash.Hash, error) {
	algo := uint32(tag.HASH_MD5)
	if rpm.Header.HasTag(tag.FILEDIGESTALGO) {
		vals, err := rpm.Header.GetUint32s(tag.FILEDIGESTALGO)
		if err != nil {
			return nil, err
		}
		// rpm writes one value; some writers repeat it for every file
		if len(vals) == 0 {
			return nil, errors.New("rpm: empty FILEDIGESTALGO")
		}
		algo = vals[0]
		for _, v := range vals[1:] {
			if v != algo {
				return nil, errors.New("rpm: FILEDIGESTALGO mixes digest algorithms")
			}
		}
	}
	return digestFor(algo)
}

// digestFor returns the constructor of the hash with the given OpenPGP
// algorithm number.
func digestFor(algo uint32) (func() hash.Hash, error) {
	switch algo {
	case tag.HASH_MD5:
		return md5.New, nil
	case tag.HASH_SHA1:
		return sha1.New, nil
	case tag.HASH_SHA224:
		return sha256.New224, nil
	case tag.HASH_SHA256:
		return sha256.New, nil
	case tag.HASH_SHA384:
		return sha512.New384, nil
	case tag.HASH_SHA512:
		return sha512.New, nil
	case tag.HASH_SHA3_256:
		return func() hash.Hash { return sha3.New256() }, nil
	case tag.HASH_SHA3_512:
		return func() hash.Hash { return sha3.New512() }, nil
	}
	return nil, fmt.Errorf("rpm: unsupported file digest algorithm %d (set ExpandOptions.SkipDigests to extract anyway)", algo)
}
