package adb

import (
	"errors"
	"io"
	"slices"
)

// ParsePackage reads the metadata and the list of files of a package from r.
// It checks the structure of the ADB block but neither the signatures nor the
// content of the files; use [VerifyPackage] or [Extract] for that.
func ParsePackage(r io.Reader, opts ReadOptions) (*Package, error) {
	rd, err := NewReader(r, opts)
	if err != nil {
		return nil, err
	}

	defer func() { _ = rd.Close() }()

	return rd.Package()
}

// VerifyPackage reads all of a package: it checks the signatures against kr,
// the digest of every file and the structure of the container. It returns the
// package and the id of the key that verified it.
//
// It fails with [ErrUnsigned] when the package has no signature,
// [ErrNoKeyring] when kr holds no key, [ErrBadSignature] when a signature of a
// trusted key does not verify and [ErrUntrusted] when no signature is by a
// trusted key.
func VerifyPackage(r io.Reader, kr *Keyring, opts ReadOptions) (*Package, KeyID, error) {
	rd, err := NewReader(r, opts)
	if err != nil {
		return nil, KeyID{}, err
	}

	defer func() { _ = rd.Close() }()

	id, err := rd.Verify(kr)
	if err != nil {
		return nil, KeyID{}, err
	}

	pkg, err := rd.Package()
	if err != nil {
		return nil, KeyID{}, err
	}

	if err := drain(rd); err != nil {
		return nil, KeyID{}, err
	}

	return pkg, id, nil
}

// drain reads every entry of a package to its end, which checks the digests.
func drain(rd *Reader) error {
	for {
		_, err := rd.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return err
		}

		if _, err := io.Copy(io.Discard, rd); err != nil {
			return err
		}
	}
}

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)

	return n, err
}

// IndexEntry reads a whole package from r and returns the entry an index lists
// for it: the metadata of the package, the SHA-256 of its ADB block as the
// identity hash and the size of the file. The package is read to its end and
// checked as [VerifyPackage] does, apart from the signatures.
func IndexEntry(r io.Reader, opts ReadOptions) (Info, error) {
	cr := &countReader{r: r}

	rd, err := NewReader(cr, opts)
	if err != nil {
		return Info{}, err
	}

	defer func() { _ = rd.Close() }()

	if _, err := rd.Package(); err != nil {
		return Info{}, err
	}

	if err := drain(rd); err != nil {
		return Info{}, err
	}

	if _, err := io.Copy(io.Discard, cr); err != nil {
		return Info{}, readErr(err)
	}

	return rd.IndexInfo(cr.n)
}

// ParseIndex reads a repository index from r. The signatures are not checked;
// use [VerifyIndex] for that.
func ParseIndex(r io.Reader, opts ReadOptions) (*Index, error) {
	rd, err := NewReader(r, opts)
	if err != nil {
		return nil, err
	}

	defer func() { _ = rd.Close() }()

	return rd.Index()
}

// VerifyIndex reads a repository index and checks its signatures against kr,
// returning the index and the id of the key that verified it. The errors are
// those of [VerifyPackage].
func VerifyIndex(r io.Reader, kr *Keyring, opts ReadOptions) (*Index, KeyID, error) {
	rd, err := NewReader(r, opts)
	if err != nil {
		return nil, KeyID{}, err
	}

	defer func() { _ = rd.Close() }()

	id, err := rd.Verify(kr)
	if err != nil {
		return nil, KeyID{}, err
	}

	idx, err := rd.Index()
	if err != nil {
		return nil, KeyID{}, err
	}

	return idx, id, nil
}

// BuildIndex writes the repository index idx to w, signed by the signers of
// opts. The entries come out sorted as apk sorts them: by name, then version.
// Entries are normally made with [IndexEntry]. Errors for an index it refuses
// wrap [ErrInvalidSpec].
func BuildIndex(w io.Writer, idx *Index, opts WriteOptions) error {
	b := newBuilder()

	pkgs := make([]*Info, len(idx.Packages))
	for i := range idx.Packages {
		pkgs[i] = &idx.Packages[i]
	}

	slices.SortStableFunc(pkgs, func(x, y *Info) int { return compareInfo(x, y) })

	slots := make([]value, 1, len(pkgs)+1)

	for _, in := range pkgs {
		is, err := b.info(in, true)
		if err != nil {
			return err
		}

		slots = append(slots, b.object(typeObject, is))
	}

	root := make([]value, ndxPkgnameSpec+1)
	root[ndxDescription] = b.str(idx.Description)
	root[ndxPkgnameSpec] = b.str(idx.PkgnameSpec)
	root[ndxPackages] = b.object(typeObject, slots)

	raw, err := b.finish(b.object(typeObject, root))
	if err != nil {
		return err
	}

	return writeFile(w, SchemaIndex, raw, opts, nil)
}
