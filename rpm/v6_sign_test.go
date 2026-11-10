package rpm

import (
	"bytes"
	"io"
	"sort"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/ProtonMail/go-crypto/openpgp"
)

// signV6 signs data (a whole RPM) with entity the way detached signers do:
// SignRpmStream + DumpSignatureHeader + the unmodified header and payload.
func signV6Bytes(t *testing.T, data []byte, entity *openpgp.Entity, sameSize bool) (*RpmHeader, []byte) {
	t.Helper()
	hdr, err := SignRpmStream(bytes.NewReader(data), entity.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	head, err := hdr.DumpSignatureHeader(sameSize)
	if err != nil {
		t.Fatal(err)
	}
	out := append(head, data[hdr.OriginalSignatureHeaderSize():]...)
	return hdr, out
}

func TestV6SignRoundTrip(t *testing.T) {
	entity, err := openpgp.NewEntity("v6 signer", "", "v6@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ref-v6.rpm", "ref-v6s.rpm"} {
		for _, sameSize := range []bool{false, true} {
			data := readV6(t, name)
			_, signed := signV6Bytes(t, data, entity, sameSize)

			// The signature header keeps its size (RESERVED absorbs the
			// signature), so the header and payload stay at their offsets.
			if len(signed) != len(data) {
				t.Fatalf("%s sameSize=%v: size changed %d -> %d", name, sameSize, len(data), len(signed))
			}

			hdr, sigs, err := Verify(bytes.NewReader(signed), openpgp.EntityList{entity})
			if err != nil {
				t.Fatalf("%s: verify: %v", name, err)
			}
			// Existing signatures are replaced, not accumulated.
			if len(sigs) != 1 || !sigs[0].HeaderOnly || sigs[0].KeyId != entity.PrimaryKey.KeyId {
				t.Fatalf("%s: unexpected signatures %+v", name, sigs)
			}
			if hdr.Format() != 6 {
				t.Fatalf("%s: format %d", name, hdr.Format())
			}

			// v6 forbids signature tags above 999 and keeps RESERVED last.
			tags := sigTags(t, signed)
			for _, id := range tags {
				if id > tag.SIG_RESERVED {
					t.Fatalf("%s: illegal v6 signature tag %d", name, id)
				}
			}
			if tags[len(tags)-1] != tag.SIG_RESERVED {
				t.Fatalf("%s: RESERVED is not the last tag: %v", name, tags)
			}

			// The original key no longer verifies: its signature was replaced.
			if _, _, err := Verify(bytes.NewReader(signed), v6Keyring(t)); err == nil {
				t.Fatalf("%s: verified with the replaced key", name)
			}
		}
	}
}

func TestV6SignRejectsCorruptPayload(t *testing.T) {
	entity, err := openpgp.NewEntity("v6 signer", "", "v6@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	data := readV6(t, "ref-v6.rpm")
	data[len(data)-1] ^= 0xff
	if _, err := SignRpmStream(bytes.NewReader(data), entity.PrivateKey, nil); err == nil {
		t.Fatal("signed a package whose payload does not match its digest")
	}
}

// sigTags returns the tag numbers of the signature header index, skipping the
// region tag.
func sigTags(t *testing.T, data []byte) []int {
	t.Helper()
	r := bytes.NewReader(data)
	if _, err := io.CopyN(io.Discard, r, 96); err != nil {
		t.Fatal(err)
	}
	h, err := readHeader(r, "", 0, false, true, HeaderLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var tags []int
	for id := range h.entries {
		if id != tag.RPMTAG_HEADERSIGNATURES {
			tags = append(tags, id)
		}
	}
	sort.Ints(tags)
	return tags
}
