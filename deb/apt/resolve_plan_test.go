package apt

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// planNames renders the plan as "Kind name=version" lines, sorted by the
// plan's own order.
func planNames(p *Plan) []string {
	out := make([]string, 0, len(p.Changes))
	for _, ch := range p.Changes {
		out = append(out, ch.Kind.String()+" "+ch.Package.Name+"="+ch.Package.Version)
	}

	return out
}

type planCase struct {
	name   string
	index  string
	status string
	req    PlanRequest
	opts   PlanOptions
	pol    candidatePolicy
	want   []string
	held   []string
	unres  []string
}

func runPlanCases(t *testing.T, cases []planCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cacheWithStatus(t, tc.index, tc.status)

			got, err := c.plan(tc.req, tc.opts, tc.pol)
			require.NoError(t, err)
			assert.Equal(t, tc.want, planNames(got))

			var held []string
			for _, h := range got.Held {
				held = append(held, h.Name)
			}

			assert.Equal(t, tc.held, held)
			assert.Equal(t, tc.unres, got.Unresolved)
		})
	}
}

func TestPlanInstall(t *testing.T) {
	runPlanCases(t, []planCase{
		{
			name: "chain",
			index: stanza("a", "1", "Depends: b") + stanza("b", "1", "Depends: c") +
				stanza("c", "1"),
			req:  PlanRequest{Install: []string{"a"}},
			want: []string{"install c=1", "install b=1", "install a=1"},
		},
		{
			name:   "already installed",
			index:  stanza("a", "1"),
			status: installedStanza("a", "1"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{},
		},
		{
			name:   "upgrade explicit",
			index:  stanza("a", "2"),
			status: installedStanza("a", "1"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"upgrade a=2"},
		},
		{
			name:  "unknown",
			index: stanza("a", "1"),
			req:   PlanRequest{Install: []string{"nothere", "a"}},
			want:  []string{"install a=1"}, unres: []string{"nothere"},
		},
		{
			name:  "alternative picks first available",
			index: stanza("a", "1", "Depends: x | y") + stanza("y", "1"),
			req:   PlanRequest{Install: []string{"a"}},
			want:  []string{"install y=1", "install a=1"},
		},
		{
			name:  "virtual provider",
			index: stanza("a", "1", "Depends: mta") + stanza("m", "1", "Provides: mta"),
			req:   PlanRequest{Install: []string{"a"}},
			want:  []string{"install m=1", "install a=1"},
		},
		{
			name:  "version pin on request",
			index: stanza("a", "1") + stanza("a", "2"),
			req:   PlanRequest{Install: []string{"a (= 1)"}},
			want:  []string{"install a=1"},
		},
	})
}

func TestPlanConflictRemoves(t *testing.T) {
	runPlanCases(t, []planCase{
		{
			name:   "installed package conflicts",
			index:  stanza("a", "2", "Conflicts: b"),
			status: installedStanza("b", "1"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"remove b=1", "install a=2"},
		},
		{
			name:   "versioned conflict out of range",
			index:  stanza("a", "2", "Conflicts: b (<< 2)"),
			status: installedStanza("b", "2"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"install a=2"},
		},
		{
			name:   "versioned conflict in range",
			index:  stanza("a", "2", "Conflicts: b (<< 2)"),
			status: installedStanza("b", "1"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"remove b=1", "install a=2"},
		},
		{
			name:   "conflict removes what depends on the removed",
			index:  stanza("a", "2", "Conflicts: b"),
			status: installedStanza("b", "1") + installedStanza("c", "1", "Depends: b"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"remove c=1", "remove b=1", "install a=2"},
		},
		{
			name:   "conflict with a provider",
			index:  stanza("a", "2", "Conflicts: mta"),
			status: installedStanza("m", "1", "Provides: mta"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"remove m=1", "install a=2"},
		},
		{
			name:   "replaces with conflicts",
			index:  stanza("a", "2", "Conflicts: b", "Replaces: b"),
			status: installedStanza("b", "1"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"remove b=1", "install a=2"},
		},
	})
}

func TestPlanBreaksUpgrades(t *testing.T) {
	runPlanCases(t, []planCase{
		{
			name:   "breaks upgrades the broken package",
			index:  stanza("a", "2", "Breaks: b (<< 2)") + stanza("b", "2"),
			status: installedStanza("b", "1"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"upgrade b=2", "install a=2"},
		},
		{
			name:   "breaks removes when no fixing version",
			index:  stanza("a", "2", "Breaks: b (<< 2)"),
			status: installedStanza("b", "1"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"remove b=1", "install a=2"},
		},
		{
			name:   "upgrade pulls dependency upgrade",
			index:  stanza("a", "2", "Depends: b (>= 2)") + stanza("b", "2"),
			status: installedStanza("a", "1") + installedStanza("b", "1"),
			req:    PlanRequest{Install: []string{"a"}},
			want:   []string{"upgrade b=2", "upgrade a=2"},
		},
	})
}

func TestPlanRemove(t *testing.T) {
	runPlanCases(t, []planCase{
		{
			name:   "remove cascades to dependents",
			index:  "",
			status: installedStanza("a", "1", "Depends: b") + installedStanza("b", "1"),
			req:    PlanRequest{Remove: []string{"b"}},
			want:   []string{"remove a=1", "remove b=1"},
		},
		{
			name:  "remove not installed",
			index: stanza("a", "1"),
			req:   PlanRequest{Remove: []string{"a"}},
			want:  []string{},
			unres: []string{"a"},
		},
		{
			name:   "alternative saves dependent",
			index:  "",
			status: installedStanza("a", "1", "Depends: b | c") + installedStanza("b", "1") + installedStanza("c", "1"),
			req:    PlanRequest{Remove: []string{"b"}},
			want:   []string{"remove b=1"},
		},
	})
}

func TestPlanUpgradeModes(t *testing.T) {
	index := stanza("a", "2") + stanza("b", "2", "Depends: n") + stanza("n", "1") +
		stanza("c", "2", "Conflicts: d") + stanza("d", "1")
	status := installedStanza("a", "1") + installedStanza("b", "1") +
		installedStanza("c", "1") + installedStanza("d", "1")

	runPlanCases(t, []planCase{
		{
			name: "upgrade keeps back what needs new packages", index: index, status: status,
			req:  PlanRequest{Upgrade: UpgradeSafe},
			want: []string{"upgrade a=2"}, held: []string{"b", "c"},
		},
		{
			name: "upgrade with new", index: index, status: status,
			req:  PlanRequest{Upgrade: UpgradeWithNew},
			want: []string{"upgrade a=2", "install n=1", "upgrade b=2"}, held: []string{"c"},
		},
		{
			name: "dist-upgrade removes", index: index, status: status,
			req: PlanRequest{Upgrade: UpgradeFull},
			want: []string{
				"remove d=1", "upgrade a=2", "install n=1", "upgrade b=2", "upgrade c=2",
			},
		},
		{
			name: "held package stays", index: index, status: status,
			req:  PlanRequest{Upgrade: UpgradeFull},
			opts: PlanOptions{Held: []string{"a"}},
			want: []string{"remove d=1", "install n=1", "upgrade b=2", "upgrade c=2"},
			// a is held at version 1
			held: []string{"a"},
		},
	})
}

func TestPlanError(t *testing.T) {
	c := cacheWithStatus(t, stanza("a", "1", "Depends: ghost")+
		stanza("x", "1", "Conflicts: y")+stanza("y", "1"), "")

	_, err := c.Plan(PlanRequest{Install: []string{"a"}}, PlanOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnresolvable)
	assert.ErrorIs(t, err, ErrUnsatisfiable)

	var pe *PlanError

	require.True(t, errors.As(err, &pe))
	assert.Contains(t, err.Error(), "ghost")

	_, err = c.Plan(PlanRequest{Install: []string{"x", "y"}}, PlanOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConflict)
	assert.True(t, strings.Contains(err.Error(), "Conflicts") || strings.Contains(err.Error(), "conflicts"))
}
