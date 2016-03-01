// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s2k

import (
	"bytes"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"testing"

	_ "golang.org/x/crypto/ripemd160"
)

var saltedTests = []struct {
	in, out string
}{
	{"hello", "f4f7d67e"},
	{"world", "7fa5480f"},
	{"foo", "dc16293a"},
	{"bar", "06a55f98905d7f533c3b38de977740029111d52f624b696f854333cf46"},
	{"x", "96307961"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "dc357273"},
}

func TestSalted(t *testing.T) {
	serialized := []byte{
		1,                      // Salted specifier
		2,                      // sha1 Id
		1, 2, 3, 4, 5, 6, 7, 8, // salt
	}

	s2k, err := Parse(bytes.NewBuffer(serialized))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2k.(*salted); !ok {
		t.Fatal("parsed unexpected s2k: %v", s2k)
	}

	for i, test := range saltedTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		s2k.Convert(out, []byte(test.in))
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}

		buf := new(bytes.Buffer)
		if _, err := s2k.WriteTo(buf); err != nil {
			t.Error(err)
			continue
		}
		if !bytes.Equal(serialized, buf.Bytes()) {
			t.Errorf("#%d, got: %x want: %x", i, serialized, buf.Bytes())
		}
	}
}

var iteratedTests = []struct {
	in, out string
}{
	{"hello", "57e7d765"},
	{"world", "2bc40754"},
	{"foo", "d743b3d6"},
	{"bar", "4e0c40712b3076baf358c2be7a3377091bfe7460a058e75280c3a05ff4"},
	{"x", "8659f369"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "d18f440f"},
}

func TestIterated(t *testing.T) {
	serialized := []byte{
		3,                      // Iterated and Salted specifier
		2,                      // sha1 Id
		8, 7, 6, 5, 4, 3, 2, 1, // salt
		31, // encoded count
	}

	s2k, err := Parse(bytes.NewBuffer(serialized))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2k.(*iterated); !ok {
		t.Fatal("parsed unexpected s2k: %v", s2k)
	}

	for i, test := range iteratedTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		s2k.Convert(out, []byte(test.in))
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}

		buf := new(bytes.Buffer)
		if _, err := s2k.WriteTo(buf); err != nil {
			t.Error(err)
			continue
		}
		if !bytes.Equal(serialized, buf.Bytes()) {
			t.Errorf("#%d, got: %x want: %x", i, serialized, buf.Bytes())
		}
	}
}

var parseTests = []struct {
	spec, in, out string
}{
	/* Simple with SHA1 */
	{"0002", "hello", "aaf4c61d"},
	/* Salted with SHA1 */
	{"01020102030405060708", "hello", "f4f7d67e"},
	/* Iterated with SHA1 */
	{"03020102030405060708f1", "hello", "f2a57b7c"},
}

func TestParse(t *testing.T) {
	for i, test := range parseTests {
		spec, _ := hex.DecodeString(test.spec)
		buf := bytes.NewBuffer(spec)
		s2k, err := Parse(buf)
		if err != nil {
			t.Errorf("%d: Parse returned error: %s", i, err)
			continue
		}

		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		s2k.Convert(out, []byte(test.in))
		if !bytes.Equal(out, expected) {
			t.Errorf("%d: output got: %x want: %x", i, out, expected)
		}
		if testing.Short() {
			break
		}

		buf.Reset()
		if _, err := s2k.WriteTo(buf); err != nil {
			t.Errorf("%d: WriteTo returned error: %s", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), spec) {
			t.Errorf("%d: serialize got: %x, want %x", i, buf.Bytes(), spec)
		}
	}
}
