// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/rsa"
	"crypto/sha1"
	"io"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/elgamal"
	"github.com/benburkert/openpgp/errors"
	"github.com/benburkert/openpgp/s2k"
)

// PrivateKey represents a possibly encrypted private key. See RFC 4880,
// section 5.5.3.
type PrivateKey struct {
	PublicKey
	Encrypted     bool // if true then the private key is unavailable until Decrypt has been called.
	encryptedData []byte
	cipher        algorithm.Cipher
	s2k           s2k.S2K
	PrivateKey    interface{} // An *rsa.PrivateKey or *dsa.PrivateKey.
	sha1Checksum  bool
	iv            []byte
}

func NewRSAPrivateKey(currentTime time.Time, priv *rsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewRSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewDSAPrivateKey(currentTime time.Time, priv *dsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewDSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewElGamalPrivateKey(currentTime time.Time, priv *elgamal.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewElGamalPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func (pk *PrivateKey) parse(r io.Reader) (err error) {
	err = (&pk.PublicKey).parse(r)
	if err != nil {
		return
	}
	var buf [1]byte
	_, err = readFull(r, buf[:])
	if err != nil {
		return
	}

	s2kType := buf[0]

	switch s2kType {
	case 0:
		pk.s2k = nil
		pk.Encrypted = false
	case 254, 255:
		_, err = readFull(r, buf[:])
		if err != nil {
			return
		}

		var ok bool
		if pk.cipher, ok = algorithm.CipherById[buf[0]]; !ok {
			return errors.UnsupportedError("unknown cipher: " + strconv.Itoa(int(buf[0])))
		}

		pk.Encrypted = true
		pk.s2k, err = s2k.Parse(r)
		if err != nil {
			return
		}
		if s2kType == 254 {
			pk.sha1Checksum = true
		}
	default:
		return errors.UnsupportedError("deprecated s2k function in private key")
	}

	if pk.Encrypted {
		blockSize := pk.cipher.BlockSize()
		if blockSize == 0 {
			return errors.UnsupportedError("unsupported cipher in private key: " + strconv.Itoa(int(pk.cipher.Id())))
		}
		pk.iv = make([]byte, blockSize)
		_, err = readFull(r, pk.iv)
		if err != nil {
			return
		}
	}

	pk.encryptedData, err = ioutil.ReadAll(r)
	if err != nil {
		return
	}

	if !pk.Encrypted {
		return pk.parsePrivateKey(pk.encryptedData)
	}

	return
}

func mod64kHash(d []byte) uint16 {
	var h uint16
	for _, b := range d {
		h += uint16(b)
	}
	return h
}

func (pk *PrivateKey) Serialize(w io.Writer) (err error) {
	// TODO(agl): support encrypted private keys
	buf := bytes.NewBuffer(nil)
	err = pk.PublicKey.serializeWithoutHeaders(buf)
	if err != nil {
		return
	}
	buf.WriteByte(0 /* no encryption */)

	privateKeyBuf := bytes.NewBuffer(nil)
	err = pk.PublicKey.PubKeyAlgo.SerializePrivateKey(privateKeyBuf, pk.PrivateKey)
	if err != nil {
		return
	}

	ptype := packetTypePrivateKey
	contents := buf.Bytes()
	privateKeyBytes := privateKeyBuf.Bytes()
	if pk.IsSubkey {
		ptype = packetTypePrivateSubkey
	}
	err = serializeHeader(w, ptype, len(contents)+len(privateKeyBytes)+2)
	if err != nil {
		return
	}
	_, err = w.Write(contents)
	if err != nil {
		return
	}
	_, err = w.Write(privateKeyBytes)
	if err != nil {
		return
	}

	checksum := mod64kHash(privateKeyBytes)
	var checksumBytes [2]byte
	checksumBytes[0] = byte(checksum >> 8)
	checksumBytes[1] = byte(checksum)
	_, err = w.Write(checksumBytes[:])

	return
}

// Decrypt decrypts an encrypted private key using a passphrase.
func (pk *PrivateKey) Decrypt(passphrase []byte) error {
	if !pk.Encrypted {
		return nil
	}

	key := make([]byte, pk.cipher.KeySize())
	if err := pk.s2k.Convert(key, passphrase); err != nil {
		return err
	}
	block := pk.cipher.New(key)
	cfb := cipher.NewCFBDecrypter(block, pk.iv)

	data := make([]byte, len(pk.encryptedData))
	cfb.XORKeyStream(data, pk.encryptedData)

	if pk.sha1Checksum {
		if len(data) < sha1.Size {
			return errors.StructuralError("truncated private key data")
		}
		h := sha1.New()
		h.Write(data[:len(data)-sha1.Size])
		sum := h.Sum(nil)
		if !bytes.Equal(sum, data[len(data)-sha1.Size:]) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-sha1.Size]
	} else {
		if len(data) < 2 {
			return errors.StructuralError("truncated private key data")
		}
		var sum uint16
		for i := 0; i < len(data)-2; i++ {
			sum += uint16(data[i])
		}
		if data[len(data)-2] != uint8(sum>>8) ||
			data[len(data)-1] != uint8(sum) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-2]
	}

	return pk.parsePrivateKey(data)
}

func (pk *PrivateKey) parsePrivateKey(data []byte) (err error) {
	if pk.PrivateKey, err = pk.PubKeyAlgo.ParsePrivateKey(data, pk.PublicKey.PublicKey); err != nil {
		return err
	}

	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}
