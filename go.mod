module github.com/M0Rf30/pkgformat

go 1.27.0

require (
	github.com/DataDog/zstd v1.5.7
	github.com/ProtonMail/go-crypto v1.5.2
	github.com/cyphar/filepath-securejoin v0.7.0
	github.com/google/go-cmp v0.7.0
	github.com/klauspost/compress v1.20.4
	github.com/klauspost/pgzip v1.3.0
	github.com/pierrec/lz4/v4 v4.1.33
	github.com/stretchr/testify v1.12.1
	github.com/ulikunitz/xz v0.5.17
	go.uber.org/goleak v1.3.0
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto v0.58.0
	golang.org/x/mod v0.43.0
	golang.org/x/sync v0.25.0
	golang.org/x/sys v0.50.0
	modernc.org/sqlite v1.62.0
)

require (
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

retract v0.3.0 // Unfetchable: test fixture names with ':' break the module zip.
