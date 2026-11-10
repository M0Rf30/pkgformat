package gpg

import (
	"bytes"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// checkKey generates an Ed25519 key created at created, with a signing subkey;
// lifetime and subLifetime are the key lifetimes in seconds (zero: never).
func checkKey(t *testing.T, created time.Time, lifetime, subLifetime uint32) *openpgp.Entity {
	t.Helper()

	config := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Curve:           packet.Curve25519,
		Time:            func() time.Time { return created },
		KeyLifetimeSecs: lifetime,
	}

	e, err := openpgp.NewEntity("check", "", "check@example.com", config)
	if err != nil {
		t.Fatal(err)
	}

	config.KeyLifetimeSecs = subLifetime
	if err := e.AddSigningSubkey(config); err != nil {
		t.Fatal(err)
	}

	return e
}

// checkSig makes a signature with key, created at created and valid for
// lifetime seconds (zero: forever).
func checkSig(t *testing.T, key *packet.PrivateKey, created time.Time, lifetime uint32) *packet.Signature {
	t.Helper()

	sig := &packet.Signature{
		SigType:      packet.SigTypeBinary,
		CreationTime: created,
		PubKeyAlgo:   key.PubKeyAlgo,
		Hash:         crypto.SHA256,
		IssuerKeyId:  &key.KeyId,
	}
	if lifetime != 0 {
		sig.SigLifetimeSecs = &lifetime
	}

	h := crypto.SHA256.New()
	h.Write([]byte("data"))

	if err := sig.Sign(h, key, nil); err != nil {
		t.Fatal(err)
	}

	return sig
}

func TestCheckSigner(t *testing.T) {
	created := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
	signed := created.Add(time.Hour)
	hour := uint32(3600)

	sub := func(e *openpgp.Entity) *openpgp.Subkey { return &e.Subkeys[len(e.Subkeys)-1] }

	for name, tc := range map[string]struct {
		setup func(t *testing.T) (e *openpgp.Entity, key *packet.PublicKey, priv *packet.PrivateKey)
		now   time.Time
		life  uint32 // lifetime of the signature
		want  error
	}{
		"primary key": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, 0)

				return e, e.PrimaryKey, e.PrivateKey
			},
			now: signed,
		},
		"subkey": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, 0)

				return e, sub(e).PublicKey, sub(e).PrivateKey
			},
			now: signed,
		},
		"revoked primary key": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, 0)
				if err := e.RevokeKey(packet.KeyCompromised, "x", nil); err != nil {
					t.Fatal(err)
				}

				return e, sub(e).PublicKey, sub(e).PrivateKey // the subkey of a revoked key too
			},
			now:  time.Now(),
			want: ErrKeyRevoked,
		},
		"revoked subkey": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, 0)
				if err := e.RevokeSubkey(sub(e), packet.KeyCompromised, "x", nil); err != nil {
					t.Fatal(err)
				}

				return e, sub(e).PublicKey, sub(e).PrivateKey
			},
			now:  time.Now(),
			want: ErrKeyRevoked,
		},
		"expired primary key": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, hour, 0)

				return e, e.PrimaryKey, e.PrivateKey
			},
			now:  created.Add(2 * time.Hour),
			want: ErrKeyExpired,
		},
		"expired subkey of a valid key": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, hour)

				return e, sub(e).PublicKey, sub(e).PrivateKey
			},
			now:  created.Add(2 * time.Hour),
			want: ErrKeyExpired,
		},
		"expired signature": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, 0)

				return e, e.PrimaryKey, e.PrivateKey
			},
			life: 3600,
			now:  signed.Add(2 * time.Hour),
			want: ErrSignatureExpired,
		},
		"signature still valid": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, 0)

				return e, e.PrimaryKey, e.PrivateKey
			},
			life: 3600,
			now:  signed.Add(time.Minute),
		},
		"signature made in the future": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, 0)

				return e, e.PrimaryKey, e.PrivateKey
			},
			now:  signed.Add(-time.Minute),
			want: ErrSignatureExpired,
		},
		"key not created yet": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e := checkKey(t, created, 0, 0)

				return e, e.PrimaryKey, e.PrivateKey
			},
			now:  created.Add(-time.Hour),
			want: ErrKeyExpired,
		},
		"a key that is not of the entity": {
			setup: func(t *testing.T) (*openpgp.Entity, *packet.PublicKey, *packet.PrivateKey) {
				e, other := checkKey(t, created, 0, 0), checkKey(t, created, 0, 0)

				return e, other.PrimaryKey, other.PrivateKey
			},
			now:  signed,
			want: ErrUnknownSigner,
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, key, priv := tc.setup(t)
			sig := checkSig(t, priv, signed, tc.life)

			if err := CheckSigner(e, key, sig, tc.now); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("CheckSigner = %v, want %v", err, tc.want)
			}
		})
	}

	if err := CheckSigner(nil, nil, nil, time.Now()); !errors.Is(err, ErrUnknownSigner) {
		t.Errorf("nil arguments: %v", err)
	}
}

// TestVerifyRevokedKeys checks that the verify helpers refuse a signature
// made by a revoked subkey, as well as one by a revoked primary key.
func TestVerifyRevokedKeys(t *testing.T) {
	for name, revoke := range map[string]func(e *openpgp.Entity) error{
		"primary": func(e *openpgp.Entity) error { return e.RevokeKey(packet.KeyCompromised, "x", nil) },
		"subkey": func(e *openpgp.Entity) error {
			return e.RevokeSubkey(&e.Subkeys[len(e.Subkeys)-1], packet.KeyCompromised, "x", nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := checkKey(t, time.Now().Add(-time.Hour), 0, 0)
			data := []byte("data")

			var sig bytes.Buffer
			if err := openpgp.DetachSign(&sig, e, bytes.NewReader(data), nil); err != nil {
				t.Fatal(err)
			}

			kr, err := ParseKeyring(binaryPublic(t, e))
			if err != nil {
				t.Fatal(err)
			}

			if _, err := VerifyDetached(kr, bytes.NewReader(data), sig.Bytes()); err != nil {
				t.Fatalf("before the revocation: %v", err)
			}

			if err := revoke(e); err != nil {
				t.Fatal(err)
			}

			kr, err = ParseKeyring(binaryPublic(t, e))
			if err != nil {
				t.Fatal(err)
			}

			if _, err := VerifyDetached(kr, bytes.NewReader(data), sig.Bytes()); !errors.Is(err, ErrKeyRevoked) {
				t.Fatalf("after the revocation: err = %v, want ErrKeyRevoked", err)
			}
		})
	}
}

func TestKeyringEntities(t *testing.T) {
	var none *Keyring
	if got := none.Entities(); got != nil {
		t.Errorf("nil keyring: %v", got)
	}

	a, b := smallEntity(t, "a"), smallEntity(t, "b")

	ring, err := ParseKeyring(armoredPublic(t, a))
	if err != nil {
		t.Fatal(err)
	}

	second, err := ParseKeyring(armoredPublic(t, b))
	if err != nil {
		t.Fatal(err)
	}

	ring.Merge(second)

	got := ring.Entities()
	if len(got) != 2 || got[0].PrimaryKey.KeyId != a.PrimaryKey.KeyId || got[1].PrimaryKey.KeyId != b.PrimaryKey.KeyId {
		t.Errorf("entities = %v", got)
	}

	// the slice is a copy
	got[0] = nil

	if ring.Entities()[0] == nil {
		t.Error("Entities returned the keyring's own slice")
	}
}
