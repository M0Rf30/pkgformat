package deb

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
)

// DebsigPolicyKeyring is the keyring file name a DebsigPolicy refers to when
// none is given.
const DebsigPolicyKeyring = "debsig.gpg"

var debsigKeyID = regexp.MustCompile(`^[0-9A-Fa-f]{16}$|^[0-9A-Fa-f]{40}$`)

// DebsigPolicy describes the policy debsig-verify applies to packages signed
// under the "origin" role: the signature must come from one key.
//
// Install the result as /etc/debsig/policies/<ID>/<name>.pol and the binary
// keyring holding the public key (gpg --export) as
// /usr/share/debsig/keyrings/<ID>/<Keyring>, where <ID> is the long key id.
type DebsigPolicy struct {
	// Name and Description label the origin.
	Name        string
	Description string
	// KeyID is the 16-digit key id (or 40-digit fingerprint) of the signing
	// key.
	KeyID string
	// Keyring is the keyring file name under /usr/share/debsig/keyrings/<ID>.
	// Empty means DebsigPolicyKeyring.
	Keyring string
}

type debsigRequired struct {
	Type string `xml:"Type,attr"`
	File string `xml:"File,attr"`
	ID   string `xml:"id,attr"`
}

type debsigOrigin struct {
	Name        string `xml:"Name,attr"`
	ID          string `xml:"id,attr"`
	Description string `xml:"Description,attr"`
}

type debsigSelection struct {
	Required debsigRequired
}

type debsigVerification struct {
	MinOptional int `xml:"MinOptional,attr"`
	Required    debsigRequired
}

type debsigPolicyXML struct {
	XMLName      xml.Name `xml:"Policy"`
	Xmlns        string   `xml:"xmlns,attr"`
	Origin       debsigOrigin
	Selection    debsigSelection
	Verification debsigVerification
}

// Marshal renders the policy file. It fails with ErrInvalidSpec for a missing
// name or a malformed key id.
func (p DebsigPolicy) Marshal() ([]byte, error) {
	if p.Name == "" {
		return nil, fmt.Errorf("%w: debsig policy needs a name", ErrInvalidSpec)
	}

	if !debsigKeyID.MatchString(p.KeyID) {
		return nil, fmt.Errorf("%w: debsig policy key id %q is not 16 or 40 hex digits", ErrInvalidSpec, p.KeyID)
	}

	keyring := p.Keyring
	if keyring == "" {
		keyring = DebsigPolicyKeyring
	}

	req := debsigRequired{Type: debsigsRoleOrigin, File: keyring, ID: p.KeyID}

	doc := debsigPolicyXML{
		Xmlns:        "https://www.debian.org/debsig/1.0/",
		Origin:       debsigOrigin{Name: p.Name, ID: p.KeyID, Description: p.Description},
		Selection:    debsigSelection{Required: req},
		Verification: debsigVerification{Required: req},
	}

	var buf bytes.Buffer

	buf.WriteString(xml.Header)
	buf.WriteString("<!DOCTYPE Policy SYSTEM \"https://www.debian.org/debsig/1.0/policy.dtd\">\n")

	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")

	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("deb: encoding debsig policy: %w", err)
	}

	buf.WriteByte('\n')

	return buf.Bytes(), nil
}
