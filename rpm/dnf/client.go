package dnf

import (
	"sync"
)

// Client reads repository configuration, refreshes repository metadata,
// indexes it and downloads packages. It is safe for concurrent use. Build one
// with [New].
type Client struct {
	opts Options
	// vars memoizes the files of Options.VarsDir by variable name: a
	// *string, nil for a variable without a file.
	vars sync.Map
}

// New returns a Client for opts. Nothing is read or fetched until a method
// runs.
func New(opts Options) *Client {
	opts.normalize()

	return &Client{opts: opts}
}
