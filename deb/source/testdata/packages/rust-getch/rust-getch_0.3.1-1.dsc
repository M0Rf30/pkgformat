-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: rust-getch
Binary: librust-getch-dev
Architecture: any
Version: 0.3.1-1
Maintainer: Debian Rust Maintainers <pkg-rust-maintainers@alioth-lists.debian.net>
Uploaders:  NoisyCoil <noisycoil@tutanota.com>
Homepage: https://nest.pijul.com/pmeunier/getch
Standards-Version: 4.7.0
Vcs-Browser: https://salsa.debian.org/rust-team/debcargo-conf/tree/master/src/getch
Vcs-Git: https://salsa.debian.org/rust-team/debcargo-conf.git [src/getch]
Testsuite: autopkgtest
Testsuite-Triggers: dh-cargo, rustc
Build-Depends: debhelper-compat (= 13), dh-sequence-cargo, cargo:native <!nocheck>, rustc:native <!nocheck>, libstd-rust-dev <!nocheck>, librust-termios-0.3+default-dev (>= 0.3.3-~~) <!nocheck>
Package-List:
 librust-getch-dev deb rust optional arch=any
Checksums-Sha1:
 3c562854154c566f0b603aa686cceb43a22245e3 1501 rust-getch_0.3.1.orig.tar.gz
 76eed98dd32d9aa7e9e98dd8c1926f0134da6f00 2068 rust-getch_0.3.1-1.debian.tar.xz
Checksums-Sha256:
 13990e2d5b29e1770ddf7fc000afead4acb9bd8f8a9602de63bf189e261b1ba8 1501 rust-getch_0.3.1.orig.tar.gz
 0efa34c0a4d02597ae80089b0cc296304eaa4bfc990049fbdf378a2bd693fe68 2068 rust-getch_0.3.1-1.debian.tar.xz
Files:
 3defcd4fab9ffa0de754eceb9d9c3c41 1501 rust-getch_0.3.1.orig.tar.gz
 6aacb3ad581144b36dab8c5e80e29aeb 2068 rust-getch_0.3.1-1.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQScTWEJ927Sl0a/hB7sV97Kb1Pv6QUCZwlEhgAKCRDsV97Kb1Pv
6RpVAP9WNwPPNaifNIEbfis0RW9wraUFzeAQEq9XXEkr3ZL9uAD8CsrfujuoCg4O
bzhNhgTNueqzkn+WJ6KlZ7Jl0h5zxQ8=
=nA5O
-----END PGP SIGNATURE-----
