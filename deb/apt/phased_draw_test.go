package apt

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhasedDrawMatchesLibstdcxx(t *testing.T) {
	t.Parallel()

	f, err := os.Open(filepath.Join("testdata", "phased", "draw.tsv"))
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)

	n := 0

	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		require.Len(t, cols, 6)

		want99, err := strconv.Atoi(cols[4])
		require.NoError(t, err)

		want100, err := strconv.Atoi(cols[5])
		require.NoError(t, err)

		raw, err := hex.DecodeString(cols[3])
		require.NoError(t, err)

		seed := cols[0] + "-" + cols[1] + "-" + cols[2]
		words := make([]uint32, len(seed))

		for i := range len(seed) {
			words[i] = uint32(int32(int8(seed[i])))
		}

		got := seedSeqGenerate(words, seedSeqWords)
		for i := range got {
			assert.Equal(t, binary.BigEndian.Uint32(raw[4*i:]), got[i], "seed_seq word %d of %q", i, seed)
		}

		assert.Equal(t, want99, PhasedDraw(cols[0], cols[1], cols[2], PhasedCurrent), "draw 0..99 of %q", seed)
		assert.Equal(t, want100, PhasedDraw(cols[0], cols[1], cols[2], PhasedPre33), "draw 0..100 of %q", seed)
		n++
	}

	require.NoError(t, sc.Err())
	require.Greater(t, n, 300)
}
