#!/bin/sh
# Runs inside the Fedora container started by ../generate.sh: builds the
# fixture packages from the specs next to it, registers them, with a few real
# distribution packages, in a throw-away root, and writes what rpm says about
# the result to /out.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dnf -y -q install rpm-build python3-rpm > /dev/null
mkdir -p /tmp/rpms /tmp/top /tmp/r /out

build() { rpmbuild -bb --quiet --define '_topdir /tmp/top' "$@" 2> /dev/null; }
r() { rpm --root /tmp/r "$@"; }

for spec in qdb-base qdb-old qdb-x; do
	build "$here/$spec.spec"
done
build --define 'libver 1.5' --define 'librel 2' "$here/qdb-lib.spec"
build --define 'libver 1.4' --define 'librel 1' "$here/qdb-lib.spec"
build --target i686 --define 'libver 1.5' --define 'librel 2' "$here/qdb-lib.spec"
find /tmp/top/RPMS -name '*.rpm' -exec cp {} /tmp/rpms/ \;

# Real packages with lua scriptlets, triggers and file triggers.
dnf -y -q download --destdir /tmp/rpms --releasever=43 shared-mime-info info fontconfig bash
rm -f /tmp/rpms/fontconfig*.i686.rpm /tmp/rpms/info*.i686.rpm /tmp/rpms/bash*.i686.rpm /tmp/rpms/shared-mime-info*.i686.rpm

r --initdb
install() { r -i --justdb --nodeps --noscripts --nosignature --nodigest --replacefiles "$@"; }
# qdb-x goes in last, on its own, so that its copy of a file of qdb-old
# replaces that one: rpm marks the file replaced in qdb-old.
install $(ls /tmp/rpms/*.rpm | grep -v '/qdb-x-')
install /tmp/rpms/qdb-x-*.rpm

cp "$(ls /tmp/r/var/lib/rpm/rpmdb.sqlite /tmp/r/usr/lib/sysimage/rpm/rpmdb.sqlite 2> /dev/null | head -n 1)" /out/db
{ rpm --version; echo "db backend: $(rpm --eval '%_db_backend')"; } > /out/info

# Records of the same shape as the other fixtures, keyed by NEVRA, plus the
# weak dependencies, conflicts and obsoletes.
QF='P\t%{=NEVRA}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n'
for rec in D:PROVIDE Q:REQUIRE C:CONFLICT O:OBSOLETE W:RECOMMEND S:SUGGEST U:SUPPLEMENT E:ENHANCE; do
	t=${rec#*:}
	QF=$QF"[${rec%%:*}\t%{=NEVRA}\t%{${t}NAME}\t%{${t}FLAGS}\t%{${t}VERSION}\n]"
done
QF=$QF'[F\t%{=NEVRA}\t%{FILENAMES}\t%{FILEMODES}\t%{FILESIZES}\t%{FILEDIGESTS}\t%{FILELINKTOS}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILEMTIMES}\t%{FILEFLAGS}\n]'
QF=$QF'[N\t%{=NEVRA}\t%{FILENAMES}\t%{FILESTATES}\n]'
# The flags of the scriptlets and the priorities of the file triggers, which
# the text of --scripts does not show; (none) for what a package lacks.
QF=$QF'X\t%{NEVRA}\t%{PRETRANSFLAGS}\t%{PREINFLAGS}\t%{POSTINFLAGS}\t%{PREUNFLAGS}\t%{POSTUNFLAGS}\t%{POSTTRANSFLAGS}\t%{PREUNTRANSFLAGS}\t%{POSTUNTRANSFLAGS}\t%{VERIFYSCRIPTFLAGS}\n'
QF=$QF'[T\t%{=NEVRA}\ttrigger\t%{TRIGGERSCRIPTFLAGS}\t0\n]'
QF=$QF'[T\t%{=NEVRA}\tfiletrigger\t%{FILETRIGGERSCRIPTFLAGS}\t%{FILETRIGGERPRIORITIES}\n]'
QF=$QF'[T\t%{=NEVRA}\ttransfiletrigger\t%{TRANSFILETRIGGERSCRIPTFLAGS}\t%{TRANSFILETRIGGERPRIORITIES}\n]'
r -qa --qf "$QF" > /out/expected

# What rpm prints for the scriptlets and triggers of every package.
r -qa --qf '%{NEVRA}\n' | sort | while read -r nevra; do
	printf '### %s\n' "$nevra"
	r -q --scripts --triggers --filetriggers "$nevra"
done > /out/scripts

# The queries. rpm's error for a query that finds nothing means no result.
query() {
	r -q "$@" --qf '%{NEVRA}\n' 2> /dev/null | grep -v -e '^error:' -e ' is not installed$' -e '^no package ' -e ' is not owned by any package$' |
		sort -u | tr '\n' ' ' | sed 's/ $//'
	true
}
tab=$(printf '\t')
while IFS="$tab" read -r kind arg; do
	case $kind in
	label) res=$(query "$arg") ;;
	file) res=$(query -f "$arg") ;;
	what*) res=$(query "--$kind" "$arg") ;;
	*) continue ;;
	esac
	printf '%s\t%s\t%s\n' "$kind" "$arg" "$res"
done < "$here/queries.txt" > /out/queries
python3 "$here/queries.py" /tmp/r "$here/queries.txt" >> /out/queries
