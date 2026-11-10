package httpclient_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/M0Rf30/pkgformat/httpclient"
)

func Example() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "Packages index")
	}))
	defer srv.Close()

	c := httpclient.New(httpclient.Options{
		Retry: httpclient.RetryPolicy{Attempts: 3, BaseDelay: 100 * time.Millisecond},
	})

	body, err := c.FetchBytes(context.Background(), srv.URL, 1<<20)
	fmt.Println(string(body), err)

	// A body over the cap is an error, never a silent truncation.
	_, err = c.FetchBytes(context.Background(), srv.URL, 4)
	fmt.Println(errors.Is(err, httpclient.ErrTooLarge))

	// Output:
	// Packages index <nil>
	// true
}
