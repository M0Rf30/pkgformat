package pacman

import "strings"

// Usage says what a repository may be used for: the Usage option of a
// pacman.conf repository section. The zero value means no Usage line, which
// pacman reads as All.
type Usage uint8

// The uses of a repository. They combine with |.
const (
	// UsageSync allows refreshing the database (pacman -Sy).
	UsageSync Usage = 1 << iota
	// UsageSearch allows searching the repository (pacman -Ss).
	UsageSearch
	// UsageInstall allows installing its packages (pacman -S pkg).
	UsageInstall
	// UsageUpgrade allows upgrading installed packages from it (pacman -Su).
	UsageUpgrade
	// UsageAll is every use.
	UsageAll = UsageSync | UsageSearch | UsageInstall | UsageUpgrade
)

// Allows reports whether u permits every use in want. The zero Usage permits
// everything.
func (u Usage) Allows(want Usage) bool {
	if u == 0 {
		return true
	}

	return u&want == want
}

// String returns the Usage option value: "All", or the names of the uses
// separated by spaces.
func (u Usage) String() string {
	if u == 0 || u == UsageAll {
		return "All"
	}

	var names []string

	for _, n := range []struct {
		use  Usage
		name string
	}{{UsageSync, "Sync"}, {UsageSearch, "Search"}, {UsageInstall, "Install"}, {UsageUpgrade, "Upgrade"}} {
		if u&n.use != 0 {
			names = append(names, n.name)
		}
	}

	return strings.Join(names, " ")
}
