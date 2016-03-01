package s2k

import (
	"io"

	"github.com/benburkert/openpgp/algorithm"
)

// Config collects configuration parameters for s2k key-stretching
// transformatioms. A nil *Config is valid and results in all default
// values. Currently, Config is used only by the Serialize function in
// this package.
type Config struct {
	// Hash is the default hash function to be used. If
	// nil, SHA1 is used.
	Hash algorithm.Hash
	// S2KCount is only used for symmetric encryption. It
	// determines the strength of the passphrase stretching when
	// the said passphrase is hashed to produce a key. S2KCount
	// should be between 1024 and 65011712, inclusive. If Config
	// is nil or S2KCount is 0, the value 65536 used. Not all
	// values in the above range can be represented. S2KCount will
	// be rounded up to the next representable value if it cannot
	// be encoded exactly. When set, it is strongly encrouraged to
	// use a value that is at least 65536. See RFC 4880 Section
	// 3.7.1.3.
	S2KCount int
	// Rand provides the source of entropy.
	Rand io.Reader
}

func (c *Config) hash() algorithm.Hash {
	if c == nil || c.Hash == nil {
		// SHA1 is the historical default in this package.
		return algorithm.SHA1
	}

	return c.Hash
}

func (c *Config) count() int {
	if c == nil || c.S2KCount == 0 {
		return 65536 // The common case. Correspoding to 65536 (96 encoded)
	}

	switch {
	// Behave like GPG. Should we make 65536 the lowest value used?
	case c.S2KCount < 1024:
		return 1024
	case c.S2KCount > 65011712:
		return 65011712
	}
	return c.S2KCount
}

// encodeCount converts an iterative "count" in the range 1024 to
// 65011712, inclusive, to an encoded count. The return value is the
// octet that is actually stored in the GPG file. encodeCount panics
// if i is not in the above range (encodedCount above takes care to
// pass i in the correct range). See RFC 4880 Section 3.7.7.1.
func encodeCount(i int) uint8 {
	if i < 1024 || i > 65011712 {
		panic("count arg i outside the required range")
	}

	for encoded := 0; encoded < 256; encoded++ {
		count := decodeCount(uint8(encoded))
		if count >= i {
			return uint8(encoded)
		}
	}

	return 255
}

// decodeCount returns the s2k mode 3 iterative "count" corresponding to
// the encoded octet c.
func decodeCount(c uint8) int {
	return (16 + int(c&15)) << (uint32(c>>4) + 6)
}
