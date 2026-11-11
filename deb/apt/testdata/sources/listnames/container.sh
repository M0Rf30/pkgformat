#!/bin/bash
# Runs inside a debian container (see generate.sh). It serves small repositories
# over http (ports 80 and 8081, IPv4 and IPv6) and https (8443) and from the
# file system, points `apt-get update` at one sources.list line at a time, and
# records which file names apt stores each index under.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
out=/out

apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 openssl gnupg apt-utils >/dev/null
rm -f /etc/apt/apt.conf.d/docker-gzip-indexes /etc/apt/apt.conf.d/docker-clean

# A signing key whose public part the sources.list lines name in signed-by.
export GNUPGHOME=/tmp/gnupg
mkdir -m 700 "$GNUPGHOME"
gpg --batch --passphrase '' --quick-gen-key 'listnames <listnames@example.invalid>' ed25519 sign never
mkdir -p /srv/key
gpg --export >/srv/key/archive.gpg
chmod -R a+rX /srv/key

# https endpoint
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem -out /tmp/cert.pem -days 2 \
	-subj /CN=127.0.0.1 -addext 'subjectAltName=IP:127.0.0.1' 2>/dev/null

cat >/tmp/server.py <<'PY'
import http.server, socket, ssl, threading


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory="/srv/http", **k)

    def log_message(self, *a):
        pass

    def finish(self):
        super().finish()
        try:
            self.connection.unwrap()  # TLS close_notify; plain sockets have none
        except Exception:
            pass


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


for port, tls in ((80, False), (8081, False), (8443, True)):
    srv = Server(("::", port), Handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

threading.Event().wait()
PY
mkdir -p /srv/http
python3 /tmp/server.py &
sleep 1

# mkrepo dir suite mode: a repository below dir. A suite ending in a slash is
# an exact path (a flat repository), anything else lives in dists/<suite>.
# mode is inrelease, detached or unsigned.
mkrepo() {
	local base=$1 suite=$2 mode=$3 dist flat=0
	case "$suite" in
	/) dist=$base flat=1 ;;
	*/) dist=$base/${suite%/} flat=1 ;;
	*) dist=$base/dists/$suite ;;
	esac
	mkdir -p "$dist"

	local pkg=$'Package: hello\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/hello_1.0_amd64.deb\nSize: 1\nSHA256: 0000000000000000000000000000000000000000000000000000000000000000\n'
	local src=$'Package: hello\nVersion: 1.0\nDirectory: pool\nFiles:\n 00000000000000000000000000000000 1 hello_1.0.dsc\n'
	local contents=$'usr/bin/hello  misc/hello\n'
	local tr=$'Package: hello\nDescription-md5: 00000000000000000000000000000000\nDescription-en: hello\n'

	if ((flat)); then
		printf '%s' "$pkg" >"$dist/Packages"
		printf '%s' "$src" >"$dist/Sources"
		printf '%s' "$contents" >"$dist/Contents-amd64"
	else
		mkdir -p "$dist/main/binary-amd64" "$dist/main/source" "$dist/main/i18n"
		printf '%s' "$pkg" >"$dist/main/binary-amd64/Packages"
		printf '%s' "$src" >"$dist/main/source/Sources"
		printf '%s' "$contents" >"$dist/main/Contents-amd64"
		printf '%s' "$tr" >"$dist/main/i18n/Translation-en"
	fi

	(
		cd "$dist"
		apt-ftparchive \
			-o APT::FTPArchive::Release::Codename=test -o APT::FTPArchive::Release::Suite=test \
			-o APT::FTPArchive::Release::Architectures=amd64 \
			-o APT::FTPArchive::Release::Components=main \
			release . >/tmp/Release
		mv /tmp/Release Release
		case "$mode" in
		inrelease) gpg --batch --yes --clearsign -o InRelease Release ;;
		detached) gpg --batch --yes --armor --detach-sign -o Release.gpg Release ;;
		unsigned) ;;
		esac
	)
}

K='signed-by=/srv/key/archive.gpg'
H=/srv/http

# line|directory|suite|mode: the sources.list line and where its repository is
# made. The directory is the file system path the URI resolves to.
cases=(
	"deb [$K] http://127.0.0.1:8081/debian stable main|$H/debian|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/debian-detached stable main|$H/debian-detached|stable|detached"
	"deb [trusted=yes] http://127.0.0.1:8081/debian-unsigned stable main|$H/debian-unsigned|stable|unsigned"
	"deb-src [$K] http://127.0.0.1:8081/debian stable main|$H/debian|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/my_repo~1/ stable main|$H/my_repo~1|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/a+b/c stable main|$H/a+b/c|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/ stable main|$H|stable|inrelease"
	"deb [$K] https://127.0.0.1:8443/secure stable main|$H/secure|stable|inrelease"
	"deb [$K] http://127.0.0.1:80/default stable main|$H/default|stable|inrelease"
	"deb [$K] http://[::1]:8081/v6 stable main|$H/v6|stable|inrelease"
	"deb [$K] http://localhost:8081/Case/Sensitive stable main|$H/Case/Sensitive|stable|inrelease"
	"deb [$K] http://user:p%40ss@127.0.0.1:8081/auth stable main|$H/auth|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/suites v1+x~rc main|$H/suites|v1+x~rc|inrelease"
	"deb [$K] http://127.0.0.1:8081/e=mc2!/x@y stable main|$H/e=mc2!/x@y|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/Sp%2541ce stable main|$H/SpAce|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/caf%C3%A9 stable main|$H/cafÃ©|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/p(1),q;r\$s stable main|$H/p(1),q;r\$s|stable|inrelease"
	"deb [$K] http://127.0.0.1:8081/flat/ ./|$H/flat|./|inrelease"
	"deb [$K] http://127.0.0.1:8081/flat2/ /|$H/flat2|/|inrelease"
	"deb [$K] http://127.0.0.1:8081/sub/dir/ sid/|$H/sub/dir|sid/|inrelease"
	"deb [$K] file:/srv/file1 stable main|/srv/file1|stable|inrelease"
	"deb [$K] file:///srv/file2 stable main|/srv/file2|stable|inrelease"
	"deb [$K] copy:/srv/file_~3 stable main|/srv/file_~3|stable|inrelease"
	"deb [$K] file:/srv/flatfile/ ./|/srv/flatfile|./|inrelease"
)

: >"$out/expected.tsv"

for entry in "${cases[@]}"; do
	IFS='|' read -r line dir suite mode <<<"$entry"
	mkrepo "$dir" "$suite" "$mode"
	chmod -R a+rX "$dir"

	rm -rf /var/lib/apt/lists
	mkdir -p /var/lib/apt/lists/partial
	printf '%s\n' "$line" >/tmp/case.list

	apt-get -q \
		-o Dir::Etc::sourcelist=/tmp/case.list -o Dir::Etc::sourceparts=/dev/null \
		-o Acquire::Languages=en -o Acquire::GzipIndexes=false -o Acquire::https::Verify-Peer=false \
		-o 'Acquire::IndexTargets::deb::Contents-deb::MetaKey=$(COMPONENT)/Contents-$(ARCHITECTURE)' \
		-o 'Acquire::IndexTargets::deb::Contents-deb::flatMetaKey=Contents-$(ARCHITECTURE)' \
		-o 'Acquire::IndexTargets::deb::Contents-deb::ShortDescription=Contents-$(ARCHITECTURE)' \
		-o 'Acquire::IndexTargets::deb::Contents-deb::Description=$(RELEASE)/$(COMPONENT) $(ARCHITECTURE) Contents' \
		-o 'Acquire::IndexTargets::deb::Contents-deb::flatDescription=$(RELEASE) Contents' \
		-o 'Acquire::IndexTargets::deb::Contents-deb::Optional=true' \
		update >/tmp/update.log 2>&1 || {
		echo "apt-get update failed for: $line" >&2
		cat /tmp/update.log >&2
		exit 1
	}

	found=0
	for path in /var/lib/apt/lists/*; do
		name=${path##*/}
		[[ $name == lock || $name == partial || $name == auxfiles ]] && continue

		rel=
		case "$name" in
		*_InRelease) rel=InRelease ;;
		*_Release.gpg) rel=Release.gpg ;;
		*_Release) rel=Release ;;
		*_main_binary-amd64_Packages) rel=main/binary-amd64/Packages ;;
		*_main_source_Sources) rel=main/source/Sources ;;
		*_main_i18n_Translation-en) rel=main/i18n/Translation-en ;;
		*_main_Contents-amd64) rel=main/Contents-amd64 ;;
		*_Contents-amd64) rel=Contents-amd64 ;;
		*_Packages) rel=Packages ;;
		*_Sources) rel=Sources ;;
		*)
			echo "unclassified list file $name for: $line" >&2
			exit 1
			;;
		esac

		printf '%s\t%s\t%s\n' "$line" "$rel" "$name" >>"$out/expected.tsv"
		found=$((found + 1))
	done
	if ((found < 2)); then
		echo "too few list files ($found) for: $line" >&2
		ls -la /var/lib/apt/lists >&2
		cat /tmp/update.log >&2
		exit 1
	fi
done

{
	echo "image: $(. /etc/os-release && echo "$PRETTY_NAME")"
	echo "apt: $(apt-get --version | head -n 1)"
	echo "captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$out/MANIFEST"
