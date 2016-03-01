// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package s2k implements the various OpenPGP string-to-key transforms as
// specified in RFC 4800 section 3.7.1.
package s2k // import "github.com/benburkert/openpgp/s2k"

import (
	"hash"
	"io"
	"strconv"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/errors"
)

type S2K interface {
	Id() uint8
	Convert(key, passphrase []byte) error
	SetupIV(size int) ([]byte, error)
	WriteTo(w io.Writer) (int, error)
}

var ParserById = map[uint8]Parser{
	0x0: Simple,
	0x1: Salted,
	0x3: Iterated,
}

type Parser func(r io.Reader) (S2K, error)

type simple struct {
	hash algorithm.Hash
}

func Simple(r io.Reader) (S2K, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	hash, ok := algorithm.HashById[buf[0]]
	if !ok {
		return nil, errors.UnsupportedError("hash for S2K function: " + strconv.Itoa(int(buf[0])))
	}

	return &simple{
		hash: hash,
	}, nil
}

func (s *simple) Id() uint8 { return 0x0 }

func (s *simple) Convert(key, passphrase []byte) error {
	convert(key, passphrase, s.hash.New(), nil, 0)
	return nil
}

func (s *simple) SetupIV(size int) ([]byte, error) { return make([]byte, size), nil }

func (s *simple) WriteTo(w io.Writer) (int, error) {
	return w.Write([]byte{s.Id(), s.hash.Id()})
}

type salted struct {
	hash algorithm.Hash
	salt []byte
}

func Salted(r io.Reader) (S2K, error) {
	var buf [9]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	hash, ok := algorithm.HashById[buf[0]]
	if !ok {
		return nil, errors.UnsupportedError("hash for S2K function: " + strconv.Itoa(int(buf[0])))
	}

	return &salted{
		hash: hash,
		salt: buf[1:],
	}, nil
}

func (s *salted) Id() uint8 { return 0x1 }

func (s *salted) Convert(key, passphrase []byte) error {
	convert(key, passphrase, s.hash.New(), s.salt, 0)
	return nil
}

func (s *salted) SetupIV(size int) ([]byte, error) { return make([]byte, size), nil }

func (s *salted) WriteTo(w io.Writer) (int, error) {
	return w.Write(append([]byte{s.Id(), s.hash.Id()}, s.salt...))
}

type iterated struct {
	hash  algorithm.Hash
	salt  []byte
	count int
}

func Iterated(r io.Reader) (S2K, error) {
	var buf [10]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	hash, ok := algorithm.HashById[buf[0]]
	if !ok {
		return nil, errors.UnsupportedError("hash for S2K function: " + strconv.Itoa(int(buf[0])))
	}

	return &iterated{
		hash:  hash,
		salt:  buf[1:9],
		count: decodeCount(buf[9]),
	}, nil
}

func New(config *Config) (S2K, error) {
	var buf [8]byte
	if _, err := io.ReadFull(config.Rand, buf[:]); err != nil {
		return nil, err
	}

	return &iterated{
		hash:  config.hash(),
		salt:  buf[:],
		count: config.count(),
	}, nil
}

func (s *iterated) Id() uint8 { return 0x3 }

func (s *iterated) Convert(key, passphrase []byte) error {
	convert(key, passphrase, s.hash.New(), s.salt, s.count)
	return nil
}

func (s *iterated) SetupIV(size int) ([]byte, error) { return make([]byte, size), nil }

func (s *iterated) WriteTo(w io.Writer) (int, error) {
	return w.Write(append([]byte{s.Id(), s.hash.Id()}, append(s.salt, encodeCount(s.count))...))
}

// Parse reads a binary specification for a string-to-key transformation from r
// and returns a function which performs that transform.
func Parse(r io.Reader) (S2K, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	parser, ok := ParserById[buf[0]]
	if !ok {
		return nil, errors.UnsupportedError("unknown S2k specifier" + strconv.Itoa(int(buf[0])))
	}

	return parser(r)
}

var zero [1]byte

func convert(out, in []byte, h hash.Hash, salt []byte, count int) {
	combined := make([]byte, len(in)+len(salt))
	copy(combined, salt)
	copy(combined[len(salt):], in)

	if count < len(combined) {
		count = len(combined)
	}

	done := 0
	var digest []byte
	for i := 0; done < len(out); i++ {
		h.Reset()
		for j := 0; j < i; j++ {
			h.Write(zero[:])
		}
		written := 0
		for written < count {
			if written+len(combined) > count {
				todo := count - written
				h.Write(combined[:todo])
				written = count
			} else {
				h.Write(combined)
				written += len(combined)
			}
		}
		digest = h.Sum(digest[:0])
		n := copy(out[done:], digest)
		done += n
	}
}
