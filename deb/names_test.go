package deb_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/M0Rf30/pkgformat/deb"
)

func TestPoolPath(t *testing.T) {
	tests := []struct {
		comp, name, file, want string
	}{
		{"main", "hello", "hello_1_amd64.deb", "pool/main/h/hello/hello_1_amd64.deb"},
		{"main", "libfoo", "libfoo_1_amd64.deb", "pool/main/libf/libfoo/libfoo_1_amd64.deb"},
		{"universe", "libssl3", "x.deb", "pool/universe/libs/libssl3/x.deb"},
		{"main", "lib", "lib_1_all.deb", "pool/main/l/lib/lib_1_all.deb"},
		{"main", "libx", "libx_1_all.deb", "pool/main/libx/libx/libx_1_all.deb"},
		{"main", "lib2to3", "x.deb", "pool/main/lib2/lib2to3/x.deb"},
		{"main", "a", "a_1_all.deb", "pool/main/a/a/a_1_all.deb"},
		{"main", "li", "x.deb", "pool/main/l/li/x.deb"},
		{"main", "library", "x.deb", "pool/main/libr/library/x.deb"},
		{"non-free", "zsh", "z.deb", "pool/non-free/z/zsh/z.deb"},
		{"main", "", "x.deb", ""},
		{"", "tool", "x.deb", "pool//t/tool/x.deb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, deb.PoolPath(tt.comp, tt.name, tt.file))
		})
	}
}

func TestFileName(t *testing.T) {
	assert.Equal(t, "hello_1.0-1_amd64.deb", deb.FileName("hello", "1.0-1", "amd64"))
	assert.Equal(t, "hello_2.0-3_all.deb", deb.FileName("hello", "1:2.0-3", "all"))
	assert.Equal(t, "a_x:b:c_all.deb", deb.FileName("a", "x:b:c", "all"), "only a numeric epoch is stripped")
	assert.Equal(t, "a_b_all.deb", deb.FileName("a", "7:b", "all"))
}

func TestRepositoryPaths(t *testing.T) {
	assert.Equal(t, "dists/stable/main/binary-amd64/Packages", deb.PackagesPath("stable", "main", "amd64", ""))
	assert.Equal(t, "dists/stable/main/binary-arm64/Packages.xz", deb.PackagesPath("stable", "main", "arm64", ".xz"))
	assert.Equal(t, "dists/stable/Release", deb.ReleasePath("stable"))
	assert.Equal(t, "dists/stable/InRelease", deb.InReleasePath("stable"))
	assert.Equal(t, "dists/stable/Release.gpg", deb.ReleaseGPGPath("stable"))
	assert.Equal(t, "dists/a/b/Release", deb.ReleasePath("a/b"))
}

func TestCompressionExtensionsAndNames(t *testing.T) {
	for name, want := range map[string]struct {
		c   deb.Compression
		ext string
	}{
		"":     {deb.CompressionZstd, ".zst"},
		"zstd": {deb.CompressionZstd, ".zst"},
		"ZST":  {deb.CompressionZstd, ".zst"},
		"gzip": {deb.CompressionGzip, ".gz"},
		"gz":   {deb.CompressionGzip, ".gz"},
		"XZ":   {deb.CompressionXZ, ".xz"},
		"none": {deb.CompressionNone, ""},
	} {
		c, err := deb.ParseCompression(name)
		assert.NoError(t, err, name)
		assert.Equal(t, want.c, c, name)
		assert.Equal(t, want.ext, c.Extension(), name)
	}

	_, err := deb.ParseCompression("bzip2")
	assert.ErrorIs(t, err, deb.ErrUnsupportedCompression)
	assert.Empty(t, deb.Compression(99).Extension())
}
