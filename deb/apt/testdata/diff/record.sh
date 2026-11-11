#!/bin/bash
# Sourced by container-worlds.sh and container.sh inside the debian container:
# defines record_plan, which runs `apt-get -s` and prints what it plans as
# tab-separated lines
#
#   <id> TAB Inst|Upgr|Down|Remv|Kept|None|Fail|Solver3 TAB <package> TAB <version>
#
#   Inst    a package that is not installed gets installed (version to install)
#   Upgr    an installed package is upgraded (new version)
#   Down    an installed package is downgraded (new version)
#   Remv    an installed package is removed (installed version)
#   Kept    an upgradable installed package is kept back (version "-")
#   None    nothing to do (package and version are "-")
#   Fail    apt-get exits with an error (package and version are "-")
#   Solver3 the first solver failed and apt's second solver produced the
#           result: the scenario says nothing about the first one
#
# Usage: record_plan <id> <apt-get arguments...>

record_plan() {
	local id=$1 result lines status
	shift

	result=$(apt-get -s --no-install-recommends "$@" 2>&1) && status=0 || status=$?

	lines=$(
		if [ "$status" -ne 0 ]; then
			printf '%s\tFail\t-\t-\n' "$id"
		else
			if grep -q 'Result calculated by the 3.0 solver' <<<"$result"; then
				printf '%s\tSolver3\t-\t-\n' "$id"
			fi
			echo "$result" | awk -v id="$id" '
				function lt(a, b) {
					return system("dpkg --compare-versions \"" a "\" lt \"" b "\"") == 0
				}
				$1 == "Inst" {
					if ($3 ~ /^\[/) {
						old = $3; gsub(/[\[\]]/, "", old)
						nv = $4; sub(/^\(/, "", nv)
						print id "\t" (lt(nv, old) ? "Down" : "Upgr") "\t" $2 "\t" nv
					} else {
						nv = $3; sub(/^\(/, "", nv)
						print id "\tInst\t" $2 "\t" nv
					}
				}
				$1 == "Remv" { v = $3; gsub(/[\[\]]/, "", v); print id "\tRemv\t" $2 "\t" v }
				/^The following packages have been kept back:/ { kept = 1; next }
				kept && /^  / { for (i = 1; i <= NF; i++) print id "\tKept\t" $i "\t-"; next }
				{ kept = 0 }
			'
		fi
	)

	if [ -n "$lines" ]; then
		printf '%s\n' "$lines"
	else
		printf '%s\tNone\t-\t-\n' "$id"
	fi
}
