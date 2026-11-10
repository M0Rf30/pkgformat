package rpm

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/gpg"
)

// keyTimes are the instants the key and signature tests are laid out on.
type keyTimes struct {
	created time.Time // the keys are created
	signed  time.Time // the packages are signed
}

func newKeyTimes() keyTimes {
	created := time.Now().Add(-72 * time.Hour).Truncate(time.Second)

	return keyTimes{created: created, signed: created.Add(time.Hour)}
}

// newEntity generates an Ed25519 key created at ts.created whose primary key
// lives for lifetime (forever when zero), with a signing subkey that lives
// for subLifetime (zero: forever).
func (ts keyTimes) newEntity(t *testing.T, lifetime, subLifetime time.Duration) *openpgp.Entity {
	t.Helper()

	config := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Curve:           packet.Curve25519,
		Time:            func() time.Time { return ts.created },
		KeyLifetimeSecs: uint32(lifetime / time.Second),
	}
	entity, err := openpgp.NewEntity("verify test", "", "verify@example.com", config)
	require.NoError(t, err)

	config.KeyLifetimeSecs = uint32(subLifetime / time.Second)
	require.NoError(t, entity.AddSigningSubkey(config))

	return entity
}

// signedWith returns pkg with its signatures replaced by those of key.
func signedWith(t *testing.T, pkg []byte, key *packet.PrivateKey, opts *SignatureOptions) []byte {
	t.Helper()

	hdr, err := SignRpmStream(bytes.NewReader(pkg), key, opts)
	require.NoError(t, err)

	head, err := hdr.DumpSignatureHeader(false)
	require.NoError(t, err)

	return append(head, pkg[hdr.OriginalSignatureHeaderSize():]...)
}

// at is a time source that always says when.
func at(when time.Time) func() time.Time { return func() time.Time { return when } }

// verifyPackages are one package of format 4 and one of format 6, so that the
// header and payload signatures of the former and the OPENPGP signature of
// the latter are both checked.
func verifyPackages(t *testing.T) map[string][]byte {
	t.Helper()

	return map[string][]byte{"v4": helloRPM(t), "v6": readV6(t, "ref-v6.rpm")}
}

func TestVerifyEnforcesKeyAndSignatureValidity(t *testing.T) {
	ts := newKeyTimes()
	sign := ts.signed

	for format, pkg := range verifyPackages(t) {
		t.Run(format, func(t *testing.T) {
			// reject checks that verification at `when` fails with a
			// *SignatureError wrapping want
			reject := func(t *testing.T, entity *openpgp.Entity, data []byte, when time.Time, want error) {
				t.Helper()

				_, _, err := VerifyWithOptions(bytes.NewReader(data), openpgp.EntityList{entity}, &VerifyOptions{Now: at(when)})
				require.ErrorIs(t, err, want)

				sigErr := &SignatureError{}
				require.ErrorAs(t, err, &sigErr)
				require.NotZero(t, sigErr.KeyID)
			}
			accept := func(t *testing.T, entity *openpgp.Entity, data []byte, when time.Time) {
				t.Helper()

				_, sigs, err := VerifyWithOptions(bytes.NewReader(data), openpgp.EntityList{entity}, &VerifyOptions{Now: at(when)})
				require.NoError(t, err)
				require.NotEmpty(t, sigs)
			}

			t.Run("valid", func(t *testing.T) {
				entity := ts.newEntity(t, 0, 0)
				data := signedWith(t, pkg, entity.PrivateKey, &SignatureOptions{CreationTime: sign})
				accept(t, entity, data, sign)
				accept(t, entity, data, time.Now())

				// the default time source is the clock
				_, sigs, err := Verify(bytes.NewReader(data), openpgp.EntityList{entity})
				require.NoError(t, err)
				require.NotEmpty(t, sigs)
			})

			t.Run("revoked primary key", func(t *testing.T) {
				entity := ts.newEntity(t, 0, 0)
				data := signedWith(t, pkg, entity.PrivateKey, &SignatureOptions{CreationTime: sign})
				accept(t, entity, data, sign)

				require.NoError(t, entity.RevokeKey(packet.KeyCompromised, "leaked", nil))
				reject(t, entity, data, time.Now(), gpg.ErrKeyRevoked)

				_, _, err := Verify(bytes.NewReader(data), openpgp.EntityList{entity})
				require.ErrorIs(t, err, gpg.ErrKeyRevoked)
			})

			t.Run("revoked subkey", func(t *testing.T) {
				entity := ts.newEntity(t, 0, 0)
				sub := &entity.Subkeys[len(entity.Subkeys)-1]
				data := signedWith(t, pkg, sub.PrivateKey, &SignatureOptions{CreationTime: sign})
				accept(t, entity, data, sign)

				require.NoError(t, entity.RevokeSubkey(sub, packet.KeyCompromised, "leaked", nil))
				reject(t, entity, data, time.Now(), gpg.ErrKeyRevoked)
			})

			t.Run("expired primary key", func(t *testing.T) {
				entity := ts.newEntity(t, 2*time.Hour, 0)
				data := signedWith(t, pkg, entity.PrivateKey, &SignatureOptions{CreationTime: sign})
				accept(t, entity, data, ts.created.Add(90*time.Minute))
				reject(t, entity, data, ts.created.Add(3*time.Hour), gpg.ErrKeyExpired)
			})

			t.Run("expired subkey", func(t *testing.T) {
				entity := ts.newEntity(t, 0, 2*time.Hour)
				sub := entity.Subkeys[len(entity.Subkeys)-1]
				data := signedWith(t, pkg, sub.PrivateKey, &SignatureOptions{CreationTime: sign})
				accept(t, entity, data, ts.created.Add(90*time.Minute))
				reject(t, entity, data, ts.created.Add(3*time.Hour), gpg.ErrKeyExpired)
			})

			t.Run("expired signature", func(t *testing.T) {
				entity := ts.newEntity(t, 0, 0)
				data := signedWith(t, pkg, entity.PrivateKey, &SignatureOptions{CreationTime: sign, Lifetime: time.Hour})
				accept(t, entity, data, sign.Add(30*time.Minute))
				reject(t, entity, data, sign.Add(2*time.Hour), gpg.ErrSignatureExpired)
			})

			t.Run("signature from the future", func(t *testing.T) {
				entity := ts.newEntity(t, 0, 0)
				data := signedWith(t, pkg, entity.PrivateKey, &SignatureOptions{CreationTime: sign})
				reject(t, entity, data, sign.Add(-time.Minute), gpg.ErrSignatureExpired)
			})

			t.Run("key created after the check", func(t *testing.T) {
				entity := ts.newEntity(t, 0, 0)
				data := signedWith(t, pkg, entity.PrivateKey, &SignatureOptions{CreationTime: sign})
				reject(t, entity, data, ts.created.Add(-time.Hour), gpg.ErrKeyExpired)
			})
		})
	}
}

func TestVerifyRequireSigned(t *testing.T) {
	ts := newKeyTimes()
	entity := ts.newEntity(t, 0, 0)
	keys := openpgp.EntityList{entity}

	for format, pkg := range verifyPackages(t) {
		t.Run(format, func(t *testing.T) {
			// the default: an unsigned package verifies, with no signatures
			_, sigs, err := Verify(bytes.NewReader(pkg), keys)
			require.NoError(t, err)
			require.Empty(t, sigs)

			// required: it does not
			_, _, err = VerifyWithOptions(bytes.NewReader(pkg), keys, &VerifyOptions{RequireSigned: true})
			require.ErrorIs(t, err, ErrUnsigned)

			// required, but nothing to check the signatures against
			_, _, err = VerifyWithOptions(bytes.NewReader(pkg), nil, &VerifyOptions{RequireSigned: true})
			require.ErrorIs(t, err, ErrNoKnownKeys)

			// a signed package passes
			signed := signedWith(t, pkg, entity.PrivateKey, &SignatureOptions{CreationTime: ts.signed})
			_, sigs, err = VerifyWithOptions(bytes.NewReader(signed), keys, &VerifyOptions{RequireSigned: true, Now: at(ts.signed)})
			require.NoError(t, err)
			require.NotEmpty(t, sigs)
		})
	}
}
