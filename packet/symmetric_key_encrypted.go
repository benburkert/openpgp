// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/cipher"
	"io"
	"strconv"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/errors"
	"github.com/benburkert/openpgp/s2k"
)

// This is the largest session key that we'll support. Since no 512-bit cipher
// has even been seriously used, this is comfortably large.
const maxSessionKeySizeInBytes = 64

// SymmetricKeyEncrypted represents a passphrase protected session key. See RFC
// 4880, section 5.3.
type SymmetricKeyEncrypted struct {
	Cipher       algorithm.Cipher
	s2k          s2k.S2K
	encryptedKey []byte
}

const symmetricKeyEncryptedVersion = 4

func (ske *SymmetricKeyEncrypted) parse(r io.Reader) error {
	// RFC 4880, section 5.3.
	var buf [2]byte
	if _, err := readFull(r, buf[:]); err != nil {
		return err
	}
	if buf[0] != symmetricKeyEncryptedVersion {
		return errors.UnsupportedError("SymmetricKeyEncrypted version")
	}

	var ok bool
	if ske.Cipher, ok = algorithm.CipherById[buf[1]]; !ok {
		return errors.UnsupportedError("unknown cipher: " + strconv.Itoa(int(buf[1])))
	}

	var err error
	ske.s2k, err = s2k.Parse(r)
	if err != nil {
		return err
	}

	encryptedKey := make([]byte, maxSessionKeySizeInBytes)
	// The session key may follow. We just have to try and read to find
	// out. If it exists then we limit it to maxSessionKeySizeInBytes.
	n, err := readFull(r, encryptedKey)
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}

	if n != 0 {
		if n == maxSessionKeySizeInBytes {
			return errors.UnsupportedError("oversized encrypted session key")
		}
		ske.encryptedKey = encryptedKey[:n]
	}

	return nil
}

// Decrypt attempts to decrypt an encrypted session key and returns the key and
// the cipher to use when decrypting a subsequent Symmetrically Encrypted Data
// packet.
func (ske *SymmetricKeyEncrypted) Decrypt(passphrase []byte) ([]byte, algorithm.Cipher, error) {
	key := make([]byte, ske.Cipher.KeySize())
	if err := ske.s2k.Convert(key, passphrase); err != nil {
		return nil, nil, err
	}

	if len(ske.encryptedKey) == 0 {
		return key, ske.Cipher, nil
	}

	// the IV is all zeros (unless an S2K extension is used)
	iv, err := ske.s2k.SetupIV(ske.Cipher.BlockSize())
	if err != nil {
		return nil, nil, err
	}

	c := cipher.NewCFBDecrypter(ske.Cipher.New(key), iv)
	plaintextKey := make([]byte, len(ske.encryptedKey))
	c.XORKeyStream(plaintextKey, ske.encryptedKey)

	cipher, ok := algorithm.CipherById[plaintextKey[0]]
	if !ok {
		return key, cipher, errors.UnsupportedError("unknown cipher: " + strconv.Itoa(int(plaintextKey[0])))
	}

	plaintextKey = plaintextKey[1:]
	if l := len(plaintextKey); l == 0 || l%cipher.BlockSize() != 0 {
		return nil, cipher, errors.StructuralError("length of decrypted key not a multiple of block size")
	}

	return plaintextKey, cipher, nil
}

// SerializeSymmetricKeyEncrypted serializes a symmetric key packet to w. The
// packet contains a random session key, encrypted by a key derived from the
// given passphrase. The session key is returned and must be passed to
// SerializeSymmetricallyEncrypted.
// If config is nil, sensible defaults will be used.
func SerializeSymmetricKeyEncrypted(w io.Writer, passphrase []byte, config *Config) (key []byte, err error) {
	s2kConfig := &s2k.Config{
		Hash:     config.Hash(),
		S2KCount: config.PasswordHashIterations(),
		Rand:     config.Random(),
	}

	s2K, err := s2k.New(s2kConfig)
	if err != nil {
		return
	}

	cipherAlgo := config.Cipher()
	keySize := cipherAlgo.KeySize()
	keyEncryptingKey := make([]byte, keySize)
	if err = s2K.Convert(keyEncryptingKey, passphrase); err != nil {
		return
	}

	s2kBuf := new(bytes.Buffer)
	if _, err = s2K.WriteTo(s2kBuf); err != nil {
		return
	}
	s2kBytes := s2kBuf.Bytes()

	packetLength := 2 /* header */ + len(s2kBytes) + 1 /* cipher type */ + keySize
	err = serializeHeader(w, packetTypeSymmetricKeyEncrypted, packetLength)
	if err != nil {
		return
	}

	var buf [2]byte
	buf[0] = symmetricKeyEncryptedVersion
	buf[1] = byte(cipherAlgo.Id())
	_, err = w.Write(buf[:])
	if err != nil {
		return
	}
	_, err = w.Write(s2kBytes)
	if err != nil {
		return
	}

	sessionKey := make([]byte, keySize)
	_, err = io.ReadFull(config.Random(), sessionKey)
	if err != nil {
		return
	}
	iv := make([]byte, cipherAlgo.BlockSize())
	c := cipher.NewCFBEncrypter(cipherAlgo.New(keyEncryptingKey), iv)
	encryptedCipherAndKey := make([]byte, keySize+1)
	c.XORKeyStream(encryptedCipherAndKey, buf[1:])
	c.XORKeyStream(encryptedCipherAndKey[1:], sessionKey)
	_, err = w.Write(encryptedCipherAndKey)
	if err != nil {
		return
	}

	key = sessionKey
	return
}
