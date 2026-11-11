#!/bin/bash
# Regenerates this directory from real tools. Needs makepkg, repo-add,
# fakeroot, zstd and bsdtar on the host and podman (or docker) with
# docker.io/library/archlinux:latest available locally; no network is used.
#
#   ./generate.sh
#
# 1. makepkg builds every package of packages.txt (empty packages whose
#    .PKGINFO carries the listed metadata) and repo-add publishes them in the
#    databases sync/{old,core,extra}.db.
# 2. In an archlinux container, pacman installs the sets of installed.txt with
#    --dbonly from file:// repositories and local/<set>/ keeps the resulting
#    local database.
# 3. Each scenario of scenarios.txt runs pacman on a copy of such a local
#    database, against the databases of sync/ with a pacman.conf written for the
#    scenario: "-S --print" or "-Su --print" for the packages pacman would
#    install, then the same transaction with --dbonly followed by "-Q" for the
#    resulting installed set. expected/<name>.txt records the outcome.
set -eu

cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman || command -v docker)}
here=$PWD

work=$(mktemp -d "${TMPDIR:-/tmp}/resolver-gen.XXXXXX")
trap 'rm -rf "$work"' EXIT

export SOURCE_DATE_EPOCH=1700000000
export PACKAGER='pkgformat tests <tests@example.invalid>'

build_package() { # repo name version [key=values...]
	local repo=$1 name=$2 version=$3 epoch=0 dir
	shift 3
	dir=$work/build/$repo/$name-$version
	mkdir -p "$dir" "$work/repo/$repo"

	case $version in *:*) epoch=${version%%:*}; version=${version#*:} ;; esac

	{
		echo "pkgname='$name'"
		echo "pkgver='${version%-*}'"
		echo "pkgrel='${version##*-}'"
		[ "$epoch" = 0 ] || echo "epoch=$epoch"
		echo "pkgdesc='resolver test package'"
		echo "arch=('any')"
		echo "options=('!debug' '!strip' '!docs' '!libtool' '!emptydirs')"
		local kv key vals v
		for kv in "$@"; do
			key=${kv%%=*}
			IFS=, read -ra vals <<<"${kv#*=}"
			printf '%s=(' "$key"
			for v in "${vals[@]}"; do printf "'%s' " "$v"; done
			echo ')'
		done
		echo 'package() { :; }'
	} >"$dir/PKGBUILD"

	(cd "$dir" && PKGDEST="$work/repo/$repo" BUILDDIR="$dir/b" \
		makepkg -f --nodeps --nocheck --skipinteg --nosign >"$dir/log" 2>&1) ||
		{ cat "$dir/log"; exit 1; }
}

repos=()
while IFS='|' read -r repo name version rest; do
	case $repo in '#'* | '') continue ;; esac
	IFS='|' read -ra kvs <<<"$rest"
	build_package "$repo" "$name" "$version" "${kvs[@]}"
	case " ${repos[*]-} " in *" $repo "*) ;; *) repos+=("$repo") ;; esac
	echo "$repo $name-${version}" >>"$work/order"
done <packages.txt

# repo-add receives the packages in the order of packages.txt.
for repo in "${repos[@]}"; do
	files=()
	while read -r r nv; do
		[ "$r" = "$repo" ] || continue
		files+=("$(ls "$work/repo/$repo/${nv%%@*}"-any.pkg.tar.zst 2>/dev/null || true)")
	done <"$work/order"
	(cd "$work/repo/$repo" && repo-add -q "$repo.db.tar.zst" "${files[@]##*/}")
done

rm -rf sync expected local
mkdir -p sync expected local
for repo in "${repos[@]}"; do
	cp -L "$work/repo/$repo/$repo.db.tar.zst" "sync/$repo.db"
done

cp installed.txt scenarios.txt "$work/"
cat >"$work/run.sh" <<'INNER'
#!/bin/bash
set -u
export LC_ALL=C TZ=UTC
cd /work

conf() { # repos usage-options ignorepkg ignoregroup
	mkdir -p /work/hooks /work/gpg /work/cache
	{
		echo "[options]"
		echo "RootDir = /work/root"
		echo "DBPath = /work/db"
		echo "CacheDir = /work/cache"
		echo "LogFile = /work/log"
		echo "GPGDir = /work/gpg"
		echo "HookDir = /work/hooks"
		echo "Architecture = x86_64"
		echo "SigLevel = Never"
		[ -z "$3" ] || echo "IgnorePkg = $3"
		[ -z "$4" ] || echo "IgnoreGroup = $4"
		local r u
		for r in $1; do
			echo "[$r]"
			echo "Server = file:///repo/$r"
			u=$(printf '%s\n' "$2" | tr ';' '\n' | sed -n "s/^Usage\.$r=//p")
			[ -z "$u" ] || echo "Usage = $u"
		done
	} >/work/pacman.conf
}

fresh() { # set
	rm -rf /work/db /work/root
	mkdir -p /work/db/sync /work/root
	if [ "$1" = empty ] || [ ! -d "/out/local/$1" ]; then
		mkdir -p /work/db/local
		echo 9 >/work/db/local/ALPM_DB_VERSION
	else
		cp -a "/out/local/$1" /work/db/local
	fi
}

pm() { pacman --config /work/pacman.conf --noconfirm "$@"; }

# refresh runs -Sy, which skips a repository whose Usage lacks Sync, then puts
# the databases in place so that such a repository is still known to pacman.
refresh() {
	pm -Sy >/dev/null 2>&1 || return 1
	for r in core extra; do cp -L "/repo/$r/$r.db" "/work/db/sync/$r.db"; done
}

mkdir -p /out/local /out/expected /out/sync

# Seed the installed sets.
while IFS='|' read -r set repos pkgs; do
	case $set in '#'* | '') continue ;; esac
	conf "$repos" "" "" ""
	fresh empty
	pm -Sy >/dev/null 2>&1 || { echo "seed $set: -Sy failed"; exit 1; }
	if [ -n "$pkgs" ]; then
		pm -S --dbonly --noscriptlet --asexplicit $pkgs >/work/seed.log 2>&1 ||
			{ cat /work/seed.log; echo "seed $set failed"; exit 1; }
	fi
	cp -a /work/db/local "/out/local/$set"
done </work/installed.txt

# Run the scenarios.
while IFS='|' read -r name mode set options targets; do
	case $name in '#'* | '') continue ;; esac
	ip= ig=
	for o in $(printf '%s\n' "$options" | tr ';' '\n' | sed 's/ /\x01/g'); do
		o=${o//$'\x01'/ }
		case $o in
		IgnorePkg=*) ip=${o#IgnorePkg=} ;;
		IgnoreGroup=*) ig=${o#IgnoreGroup=} ;;
		esac
	done
	conf "core extra" "$options" "$ip" "$ig"
	fresh "$set"
	refresh || { echo "$name: -Sy failed"; exit 1; }
	case $mode in S) flags=-S ;; Su) flags=-Su ;; *) echo "bad mode $mode"; exit 1 ;; esac
	out=/out/expected/$name.txt
	# "--print" skips the conflict check, so the real (--dbonly) transaction
	# decides whether the scenario succeeds.
	if pm $flags --dbonly --noscriptlet $targets >/work/real.log 2>&1; then
		pm -Q | sed 's/^/final /' >/work/final.txt
		fresh "$set"
		refresh
		res=$(pm $flags --print --print-format 'PKG %r %n %v' $targets 2>/work/err) ||
			{ cat /work/err; echo "$name: --print failed"; exit 1; }
		echo "status ok" >"$out"
		printf '%s\n' "$res" | sed -n 's/^PKG /pkg /p' | sort >>"$out"
		cat /work/final.txt >>"$out"
	else
		echo "status error" >"$out"
		sed -n -e 's/^error: /error /p' -e 's/^:: /info /p' /work/real.log >>"$out"
	fi
done </work/scenarios.txt
cp -a /repo/. /out/sync/ 2>/dev/null || true
INNER

mkdir -p "$work/out"
"$engine" run --rm \
	-v "$work/repo:/repo:ro,Z" \
	-v "$work:/work:Z" \
	-v "$work/out:/out:Z" \
	docker.io/library/archlinux:latest bash /work/run.sh
rm -rf "$work/out/sync"
cp -a "$work/out/expected/." expected/
cp -a "$work/out/local/." local/
{ pacman --version | grep -o 'Pacman v[0-9.a-z]*'; "$engine" run --rm docker.io/library/archlinux:latest sh -c 'pacman --version | grep -o "Pacman v[0-9.a-z]*"; grep PRETTY_NAME /etc/os-release'; } >info.txt
echo "ok: $(ls expected | wc -l) scenarios, $(ls local | wc -l) installed sets"
