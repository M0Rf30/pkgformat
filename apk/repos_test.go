package apk

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseRepositories(t *testing.T) {
	text := `# the main repository
https://dl-cdn.alpinelinux.org/alpine/v3.21/main/

  http://mirror.example.org/community  
@edge https://dl-cdn.alpinelinux.org/alpine/edge/testing
@local	https://example.org/local//
`
	got, err := ParseRepositories(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}

	want := []Repo{
		{URL: "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"},
		{URL: "http://mirror.example.org/community"},
		{URL: "https://dl-cdn.alpinelinux.org/alpine/edge/testing", Tag: "edge"},
		{URL: "https://example.org/local", Tag: "local"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	if got, err := ParseRepositories(strings.NewReader("")); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func TestParseRepositories_invalid(t *testing.T) {
	for name, text := range map[string]string{
		"tag without url": "@edge\n",
		"bare at":         "@ https://x\n",
		"two urls":        "https://a https://b\n",
		"tag two urls":    "@t https://a https://b\n",
		"slash only":      "/\n",
		"long line":       strings.Repeat("a", maxRepositoryLine+1) + "\n",
		"too large":       strings.Repeat("# comment\n", maxRepositoriesBytes/10+10),
		"too many":        strings.Repeat("https://example.org/r\n", maxRepositories+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRepositories(strings.NewReader(text)); !errors.Is(err, ErrInvalidRepositories) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
