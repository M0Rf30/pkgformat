package dnf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// monday is a Monday 00:00 UTC, the start of a countme window.
var monday = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func countmeClient(t *testing.T, draw int) (*Client, *time.Time) {
	t.Helper()

	now := monday.Add(time.Hour)
	c := New(Options{PersistDir: t.TempDir()})
	c.now = func() time.Time { return now }
	c.intn = func(int) int { return draw }

	return c, &now
}

func TestCountmeFlagOncePerWindow(t *testing.T) {
	c, now := countmeClient(t, 0)
	repo := &Repo{ID: "fedora", CountMe: true, MirrorList: "https://m.example/list"}

	if got := c.countmeFlag(repo); got != "countme=1" {
		t.Errorf("first request = %q", got)
	}

	// the rest of the window is not counted again
	for _, d := range []time.Duration{time.Minute, 24 * time.Hour, 6 * 24 * time.Hour} {
		*now = monday.Add(time.Hour + d)
		if got := c.countmeFlag(repo); got != "" {
			t.Errorf("+%v: %q", d, got)
		}
	}

	// next window, one request is enough with a budget of one
	*now = monday.Add(7*24*time.Hour + time.Minute)
	if got := c.countmeFlag(repo); got != "countme=1" {
		t.Errorf("next window = %q", got)
	}
}

func TestCountmeBudgetDelaysTheCountedRequest(t *testing.T) {
	c, now := countmeClient(t, 2) // budget of three
	repo := &Repo{ID: "r", CountMe: true, MirrorList: "https://m.example/list"}

	var got []string

	for range 4 {
		got = append(got, c.countmeFlag(repo))
		*now = now.Add(time.Minute)
	}

	// requests 1 and 2 only count down, the third is counted, the fourth is the
	// same window
	if strings.Join(got, ",") != ",,countme=1," {
		t.Errorf("flags = %q", got)
	}
}

func TestCountmeBuckets(t *testing.T) {
	// the age of the system is counted from the modification time of the
	// machine id file
	for weeks, want := range map[int]string{
		0:   "countme=1",
		1:   "countme=1",
		2:   "countme=2",
		4:   "countme=2",
		5:   "countme=3",
		24:  "countme=3",
		25:  "countme=4",
		200: "countme=4",
	} {
		c, _ := countmeClient(t, 0)
		c.opts.MachineIDFile = filepath.Join(t.TempDir(), "machine-id")

		if err := os.WriteFile(c.opts.MachineIDFile, []byte("abc\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		installed := monday.Add(time.Hour - time.Duration(weeks)*7*24*time.Hour)
		if err := os.Chtimes(c.opts.MachineIDFile, installed, installed); err != nil {
			t.Fatal(err)
		}

		repo := &Repo{ID: "r", CountMe: true, MirrorList: "https://m.example/list"}
		if got := c.countmeFlag(repo); got != want {
			t.Errorf("%d weeks: %q, want %q", weeks, got, want)
		}
	}
}

func TestCountmeOffWithoutItsPrerequisites(t *testing.T) {
	c, _ := countmeClient(t, 0)

	for name, repo := range map[string]*Repo{
		"countme off":    {ID: "r", MirrorList: "https://m.example/list"},
		"no mirror list": {ID: "r", CountMe: true, BaseURLs: []string{"https://b.example"}},
	} {
		if got := c.countmeFlag(repo); got != "" {
			t.Errorf("%s: %q", name, got)
		}
	}

	c.opts.PersistDir = ""
	if got := c.countmeFlag(&Repo{ID: "r", CountMe: true, MirrorList: "https://m.example/list"}); got != "" {
		t.Errorf("no persistdir: %q", got)
	}
}

func TestSystemEpochIgnoresUninitializedMachineID(t *testing.T) {
	c, _ := countmeClient(t, 0)
	dir := t.TempDir()

	for name, content := range map[string]string{"empty": "", "uninit": "uninitialized\n"} {
		c.opts.MachineIDFile = filepath.Join(dir, name)
		if err := os.WriteFile(c.opts.MachineIDFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		if got := c.systemEpoch(); got != 0 {
			t.Errorf("%s: epoch = %d", name, got)
		}
	}

	c.opts.MachineIDFile = filepath.Join(dir, "missing")
	if c.systemEpoch() != 0 {
		t.Error("a missing file has an epoch")
	}
}

func TestWithQuery(t *testing.T) {
	if got := withQuery("https://m/list", "countme=1"); got != "https://m/list?countme=1" {
		t.Error(got)
	}

	if got := withQuery("https://m/list?repo=x", "countme=1"); got != "https://m/list?repo=x&countme=1" {
		t.Error(got)
	}
}

func TestCountmeParameterReachesTheMirrorListOnce(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))

	var (
		mu    sync.Mutex
		query []string
	)

	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		query = append(query, r.URL.RawQuery)
		mu.Unlock()

		_, _ = w.Write([]byte(repo.url() + "\n"))
	}))
	t.Cleanup(list.Close)

	env := newEnv(t, "[test]\nmirrorlist="+list.URL+"/list?repo=x\ncountme=1\n", func(o *Options) {
		o.PersistDir = t.TempDir()
	})
	env.now = func() time.Time { return monday.Add(time.Hour) }
	env.intn = func(int) int { return 0 }

	for range 2 {
		if err := env.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	mu.Lock()
	defer mu.Unlock()

	counted := 0

	for _, q := range query {
		if !strings.HasPrefix(q, "repo=x") {
			t.Errorf("query %q lost the original parameter", q)
		}

		if strings.Contains(q, "countme=1") {
			counted++
		}
	}

	if counted != 1 || len(query) < 2 {
		t.Errorf("queries = %q", query)
	}
}
