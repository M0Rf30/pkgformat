package apk

import (
	"bytes"
	"fmt"
	"io"

	"github.com/M0Rf30/pkgformat/apk/adb"
)

// Format is the container format of a package.
type Format int

const (
	// FormatV2 is the format of apk-tools 2: concatenated gzip streams of tar.
	FormatV2 Format = iota
	// FormatV3 is the ADB format of apk-tools 3, read by package [adb].
	FormatV3
)

// String returns "v2" or "v3".
func (f Format) String() string {
	if f == FormatV3 {
		return "v3"
	}

	return "v2"
}

// isADB reports whether the file starts with an ADB magic: uncompressed
// ("ADB."), deflate ("ADBd") or with a compression spec ("ADBc").
func isADB(r io.ReaderAt, size int64) bool {
	if size < 4 {
		return false
	}

	var magic [4]byte
	if _, err := r.ReadAt(magic[:], 0); err != nil {
		return false
	}

	return bytes.Equal(magic[:3], []byte("ADB")) && (magic[3] == '.' || magic[3] == 'd' || magic[3] == 'c')
}

func parseADBPackage(r io.ReaderAt, size int64) (*Package, error) {
	p, err := adb.ParsePackage(io.NewSectionReader(r, 0, size), adb.ReadOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPackage, err)
	}

	return fromADB(p, size), nil
}

// fromADB converts an APKv3 package to the common form.
func fromADB(p *adb.Package, size int64) *Package {
	in := p.Info

	return &Package{
		Name:             in.Name,
		Version:          in.Version,
		Arch:             in.Arch,
		Description:      in.Description,
		URL:              in.URL,
		License:          in.License,
		Origin:           in.Origin,
		Maintainer:       in.Maintainer,
		Commit:           in.RepoCommit,
		BuildTime:        int64(in.BuildTime),
		InstalledSize:    int64(in.InstalledSize),
		Depends:          in.Depends,
		Provides:         in.Provides,
		Replaces:         in.Replaces,
		Triggers:         p.Triggers,
		InstallIf:        in.InstallIf,
		Recommends:       in.Recommends,
		ProviderPriority: int(in.ProviderPriority),
		ReplacesPriority: int(p.ReplacesPriority),
		Hashes:           in.Hashes,
		Size:             size,
		Format:           FormatV3,
	}
}
