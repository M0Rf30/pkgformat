package dnf

import (
	"math/rand/v2"
	"sync"
	"time"
)

// Client reads repository configuration, refreshes repository metadata,
// indexes it and downloads packages. It is safe for concurrent use. Build one
// with [New].
type Client struct {
	opts Options
	// vars memoizes the files of Options.VarsDir by variable name: a
	// *string, nil for a variable without a file.
	vars sync.Map
	// proxied memoizes the clients of httpFor by proxy URL.
	proxied sync.Map
	// keyrings memoizes the gpgkey files by URL: a *gpg.Keyring.
	keyrings sync.Map

	// cfg is the dnf.conf, read once.
	cfgOnce sync.Once
	cfg     *Config
	cfgErr  error

	// now and intn are the clock and the dice of countme, replaceable by
	// the tests.
	countmeMu sync.Mutex
	now       func() time.Time
	intn      func(n int) int
}

// New returns a Client for opts. Nothing is read or fetched until a method
// runs.
func New(opts Options) *Client {
	opts.normalize()

	return &Client{opts: opts, now: time.Now, intn: rand.IntN}
}
