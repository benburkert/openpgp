package algorithm

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"strconv"

	"github.com/benburkert/openpgp/aes/keywrap"
	"github.com/benburkert/openpgp/ecdh"
	"github.com/benburkert/openpgp/elgamal"
	"github.com/benburkert/openpgp/encoding"
	"github.com/benburkert/openpgp/errors"
)

// PublicKey represents the different public key system specified for OpenPGP.
// See http://www.iana.org/assignments/pgp-parameters/pgp-parameters.xhtml#pgp-parameters-12
type PublicKey interface {
	// Id returns the algorithm ID, as a byte, of publickey.
	Id() uint8

	// BitLength is the size in bits of the public key data.
	BitLength(pub crypto.PublicKey) (uint16, error)

	// CanEncrypt returns true if the public key algorithm supports encryption.
	CanEncrypt() bool

	// Encrypt performs asymmetric encryption on the given message. The
	// ciphertext of the encrypted message is returned as encoded fields.
	Encrypt(rand io.Reader, pub crypto.PublicKey, msg []byte, fingerprint [20]byte) ([]encoding.Field, error)

	// Decrypt performs asymmetric decryption on the ciphertext contained in
	// the encoded fields, returning the original message.
	Decrypt(rand io.Reader, priv crypto.PrivateKey, fields []encoding.Field, fingerprint [20]byte) ([]byte, error)

	// CanSign returns true if the public key algorithm supports signatures.
	CanSign() bool

	// Sign creates an asymmetric signature of the message. The signature is
	// returned as encoded fields.
	Sign(rand io.Reader, priv crypto.PrivateKey, sigopt crypto.SignerOpts, msg []byte) ([]encoding.Field, error)

	// Verify verifies the asymmetric signature of the message from the encoded
	// signature.
	Verify(pub crypto.PublicKey, sigopt crypto.SignerOpts, hashed []byte, sig []encoding.Field) error

	// ParsePrivateKey parses the private key from data for a type of public
	// key algorithm.
	ParsePrivateKey(data []byte, pub crypto.PublicKey) (crypto.PrivateKey, error)

	// ParsePrivateKey parses the public key from data for a type of public key
	// algorithm.
	ParsePublicKey(r io.Reader) (crypto.PublicKey, []encoding.Field, error)

	// ParseEncryptedKey parses the symmetric encryption session key. The key
	// is returned as encoded fields.
	ParseEncryptedKey(r io.Reader) ([]encoding.Field, error)

	// ParseSignature parses the asymmetric signature. The signature is
	// returned as encoded fields.
	ParseSignature(r io.Reader) ([]encoding.Field, error)

	// SerializePrivateKey writes the private key to the writer. The encoding
	// is determined by the public key algorithm.
	SerializePrivateKey(w io.Writer, priv crypto.PrivateKey) error
}

// The following constants mirror the OpenPGP standard (RFC 4880), as
// well as several GnuPG extensions to the standard.
const (
	RSA            = publicKey(1)
	RSAEncryptOnly = publicKey(2)
	RSASignOnly    = publicKey(3)
	ElGamal        = publicKey(16)
	DSA            = publicKey(17)
	ECDH           = publicKey(18)
	ECDSA          = publicKey(19)
)

// PublicKeyById represents the different public key cryptography options
// specified for OpenPGP. See
// http://www.iana.org/assignments/pgp-parameters/pgp-parameters.xhtml#pgp-parameters-12
var PublicKeyById = map[uint8]PublicKey{
	RSA.Id():            RSA,
	RSAEncryptOnly.Id(): RSAEncryptOnly,
	RSASignOnly.Id():    RSASignOnly,
	ElGamal.Id():        ElGamal,
	DSA.Id():            DSA,
	ECDH.Id():           ECDH,
	ECDSA.Id():          ECDSA,
}

var (
	// NIST curve P-256
	oidCurveP256 = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	// NIST curve P-384
	oidCurveP384 = []byte{0x2B, 0x81, 0x04, 0x00, 0x22}
	// NIST curve P-521
	oidCurveP521 = []byte{0x2B, 0x81, 0x04, 0x00, 0x23}
)

type publicKey uint8

func (pk publicKey) Id() uint8 {
	return uint8(pk)
}

func (pk publicKey) BitLength(pub crypto.PublicKey) (uint16, error) {
	switch pk {
	case RSA, RSAEncryptOnly, RSASignOnly:
		rsapub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return 0, errors.InvalidArgumentError("wrong type of public key")
		}

		n := new(encoding.MPI).SetBig(rsapub.N)
		return n.BitLength(), nil
	case DSA:
		dsapub, ok := pub.(*dsa.PublicKey)
		if !ok {
			return 0, errors.InvalidArgumentError("wrong type of public key")
		}

		p := new(encoding.MPI).SetBig(dsapub.P)
		return p.BitLength(), nil
	case ElGamal:
		egpub, ok := pub.(*elgamal.PublicKey)
		if !ok {
			return 0, errors.InvalidArgumentError("wrong type of public key")
		}

		p := new(encoding.MPI).SetBig(egpub.P)
		return p.BitLength(), nil
	default:
		return 0, errors.InvalidArgumentError("bad public-key algorithm")
	}
}

func (pk publicKey) CanEncrypt() bool {
	switch pk {
	case RSA, RSAEncryptOnly, ElGamal:
		return true
	default:
		return false
	}
}
func (pk publicKey) CanSign() bool {
	switch pk {
	case RSA, RSASignOnly, DSA, ECDSA:
		return true
	default:
		return false
	}
}

func (pk publicKey) Encrypt(rand io.Reader, pub crypto.PublicKey, msg []byte, fingerprint [20]byte) ([]encoding.Field, error) {
	switch pk {
	case RSA, RSAEncryptOnly:
		rsapub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.InvalidArgumentError("cannot encrypt to wrong type of public key")
		}

		cipherText, err := rsa.EncryptPKCS1v15(rand, rsapub, msg)
		if err != nil {
			return nil, errors.InvalidArgumentError("RSA encryption failed: " + err.Error())
		}

		return []encoding.Field{encoding.NewMPI(cipherText)}, nil
	case ElGamal:
		egpub, ok := pub.(*elgamal.PublicKey)
		if !ok {
			return nil, errors.InvalidArgumentError("cannot encrypt to wrong type of public key")
		}

		c1, c2, err := elgamal.Encrypt(rand, egpub, msg)
		if err != nil {
			return nil, errors.InvalidArgumentError("ElGamal encryption failed: " + err.Error())
		}

		return []encoding.Field{
			new(encoding.MPI).SetBig(c1),
			new(encoding.MPI).SetBig(c2),
		}, nil
	case ECDH:
		ecdhpub, ok := pub.(*ecdh.PublicKey)
		if !ok {
			return nil, errors.InvalidArgumentError("cannot encrypt to wrong type of public key")
		}

		kdfCipher, ok := CipherById[ecdhpub.KDF.Bytes()[2]]
		if !ok {
			return nil, errors.InvalidArgumentError("unknown KDF cipher")
		}

		// the sender MAY use 21, 13, and 5 bytes of padding for AES-128,
		// AES-192, and AES-256, respectively, to provide the same number of
		// octets, 40 total, as an input to the key wrapping method.
		padded_length := (kdfCipher.KeySize()/8+1)*8
		padding := make([]byte, padded_length-len(msg))
		for i := range padding {
			padding[i] = byte(padded_length - len(msg))
		}
		m := append(msg, padding...)

		d, x, y, err := elliptic.GenerateKey(ecdhpub.Curve, rand)
		if err != nil {
			return nil, err
		}

		vsG := elliptic.Marshal(ecdhpub.Curve, x, y)
		zb, _ := ecdhpub.Curve.ScalarMult(ecdhpub.X, ecdhpub.Y, d)

		var oid *encoding.BitString
		switch ecdhpub.Curve {
		case elliptic.P256():
			oid = encoding.NewBitString(oidCurveP256)
		case elliptic.P384():
			oid = encoding.NewBitString(oidCurveP384)
		case elliptic.P521():
			oid = encoding.NewBitString(oidCurveP521)
		default:
			return nil, errors.InvalidArgumentError("cannot encrypt with an unknown curve")
		}

		// Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
		//         || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap
		//         || "Anonymous Sender    " || recipient_fingerprint;
		param := new(bytes.Buffer)
		if _, err := oid.WriteTo(param); err != nil {
			return nil, err
		}
		if _, err := param.Write([]byte{18}); err != nil {
			return nil, err
		}
		if _, err := ecdhpub.KDF.WriteTo(param); err != nil {
			return nil, err
		}
		if _, err := param.Write([]byte("Anonymous Sender    ")); err != nil {
			return nil, err
		}
		if _, err := param.Write(fingerprint[:]); err != nil {
			return nil, err
		}
		if param.Len() != 54 && param.Len() != 51 {
			return nil, errors.InvalidArgumentError("malformed KDF Param")
		}

		kdfHash, ok := HashById[ecdhpub.KDF.Bytes()[1]]
		if !ok {
			return nil, errors.InvalidArgumentError("unknown KDF hash function")
		}

		// MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
		h := kdfHash.New()
		if _, err := h.Write([]byte{0x0, 0x0, 0x0, 0x1}); err != nil {
			return nil, err
		}
		if _, err := h.Write(zb.Bytes()); err != nil {
			return nil, err
		}
		if _, err := h.Write(param.Bytes()); err != nil {
			return nil, err
		}
		mb := h.Sum(nil)

		z := mb[:kdfCipher.KeySize()] // return oBits leftmost bits of MB.

		c, err := keywrap.Wrap(z, m)
		if err != nil {
			return nil, err
		}

		return []encoding.Field{
			encoding.NewMPI(vsG),
			encoding.NewBitString(c),
		}, nil
	case DSA, RSASignOnly, ECDSA:
		return nil, errors.InvalidArgumentError("cannot encrypt to public key of type " + strconv.Itoa(int(pk.Id())))
	}

	return nil, errors.UnsupportedError("encrypting a key to public key of type " + strconv.Itoa(int(pk)))
}

func (pk publicKey) Decrypt(rand io.Reader, priv crypto.PrivateKey, fields []encoding.Field, fingerprint [20]byte) ([]byte, error) {
	switch pk {
	case RSA, RSAEncryptOnly:
		return rsa.DecryptPKCS1v15(rand, priv.(*rsa.PrivateKey), fields[0].Bytes())
	case ElGamal:
		c1 := new(big.Int).SetBytes(fields[0].Bytes())
		c2 := new(big.Int).SetBytes(fields[1].Bytes())

		return elgamal.Decrypt(priv.(*elgamal.PrivateKey), c1, c2)
	case ECDH:
		ecdhPriv, ok := priv.(*ecdh.PrivateKey)
		if !ok {
			return nil, errors.InvalidArgumentError("cannot decrypt with wrong type of private key")
		}

		m := fields[1].Bytes()
		x, y := elliptic.Unmarshal(ecdhPriv.Curve, fields[0].Bytes())
		zb, _ := ecdhPriv.Curve.ScalarMult(x, y, ecdhPriv.D)

		var oid *encoding.BitString
		switch ecdhPriv.Curve {
		case elliptic.P256():
			oid = encoding.NewBitString(oidCurveP256)
		case elliptic.P384():
			oid = encoding.NewBitString(oidCurveP384)
		case elliptic.P521():
			oid = encoding.NewBitString(oidCurveP521)
		default:
			return nil, errors.InvalidArgumentError("cannot decrypt with an unknown curve")
		}

		// Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
		//         || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap
		//         || "Anonymous Sender    " || recipient_fingerprint;
		param := new(bytes.Buffer)
		if _, err := oid.WriteTo(param); err != nil {
			return nil, err
		}
		if _, err := param.Write([]byte{18}); err != nil {
			return nil, err
		}
		if _, err := ecdhPriv.KDF.WriteTo(param); err != nil {
			return nil, err
		}
		if _, err := param.Write([]byte("Anonymous Sender    ")); err != nil {
			return nil, err
		}
		if _, err := param.Write(fingerprint[:]); err != nil {
			return nil, err
		}
		if param.Len() != 54 && param.Len() != 51 {
			return nil, errors.InvalidArgumentError("malformed KDF Param")
		}

		kdfHash, ok := HashById[ecdhPriv.KDF.Bytes()[1]]
		if !ok {
			return nil, errors.InvalidArgumentError("unknown KDF hash function")
		}

		// MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
		h := kdfHash.New()
		if _, err := h.Write([]byte{0x0, 0x0, 0x0, 0x1}); err != nil {
			return nil, err
		}
		if _, err := h.Write(zb.Bytes()); err != nil {
			return nil, err
		}
		if _, err := h.Write(param.Bytes()); err != nil {
			return nil, err
		}
		mb := h.Sum(nil)

		kdfCipher, ok := CipherById[ecdhPriv.KDF.Bytes()[2]]
		if !ok {
			return nil, errors.InvalidArgumentError("unknown KDF cipher")
		}
		z := mb[:kdfCipher.KeySize()] // return oBits leftmost bits of MB.

		c, err := keywrap.Unwrap(z, m)
		if err != nil {
			return nil, err
		}

		return c[:len(c)-int(c[len(c)-1])], nil
	default:
		return nil, errors.InvalidArgumentError("cannot decrypted encrypted session key with private key of type " + strconv.Itoa(int(pk)))
	}
}

func (pk publicKey) Sign(rand io.Reader, priv crypto.PrivateKey, sigopt crypto.SignerOpts, digest []byte) ([]encoding.Field, error) {
	switch pk {
	case RSA, RSASignOnly:
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.InvalidArgumentError("cannot sign with wrong type of private key")
		}

		sigdata, err := rsa.SignPKCS1v15(rand, rsaPriv, sigopt.HashFunc(), digest)
		if err != nil {
			return nil, err
		}

		return []encoding.Field{encoding.NewMPI(sigdata)}, nil
	case DSA:
		dsaPriv, ok := priv.(*dsa.PrivateKey)
		if !ok {
			return nil, errors.InvalidArgumentError("cannot sign with wrong type of private key")
		}

		// Need to truncate hashBytes to match FIPS 186-3 section 4.6.
		subgroupSize := (dsaPriv.Q.BitLen() + 7) / 8
		if len(digest) > subgroupSize {
			digest = digest[:subgroupSize]
		}

		r, s, err := dsa.Sign(rand, dsaPriv, digest)
		if err != nil {
			return nil, err
		}

		return []encoding.Field{
			new(encoding.MPI).SetBig(r),
			new(encoding.MPI).SetBig(s),
		}, nil
	case ECDSA:
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.InvalidArgumentError("cannot sign with wrong type of private key")
		}

		r, s, err := ecdsa.Sign(rand, ecdsaPriv, digest)
		if err != nil {
			return nil, err
		}

		return []encoding.Field{
			new(encoding.MPI).SetBig(r),
			new(encoding.MPI).SetBig(s),
		}, nil
	default:
		return nil, errors.UnsupportedError("public key algorithm: " + strconv.Itoa(int(pk)))
	}
}

func (pk publicKey) Verify(pub crypto.PublicKey, sigopt crypto.SignerOpts, hashed []byte, sig []encoding.Field) error {
	switch pk {
	case RSA, RSASignOnly:
		rsapub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.InvalidArgumentError("cannot verify signature with wrong type of public key")
		}

		if len(sig) != 1 {
			return errors.InvalidArgumentError("cannot verify malformed signature")
		}

		return rsa.VerifyPKCS1v15(rsapub, sigopt.HashFunc(), hashed, sig[0].Bytes())
	case DSA:
		dsapub, ok := pub.(*dsa.PublicKey)
		if !ok {
			return errors.InvalidArgumentError("cannot verify signature with wrong type of public key")
		}

		if len(sig) != 2 {
			return errors.InvalidArgumentError("cannot verify malformed signature")
		}

		// Need to truncate hashBytes to match FIPS 186-3 section 4.6.
		subgroupSize := (dsapub.Q.BitLen() + 7) / 8
		if len(hashed) > subgroupSize {
			hashed = hashed[:subgroupSize]
		}

		sigR := new(big.Int).SetBytes(sig[0].Bytes())
		sigS := new(big.Int).SetBytes(sig[1].Bytes())
		if !dsa.Verify(dsapub, hashed, sigR, sigS) {
			return errors.SignatureError("DSA verification failure")
		}
		return nil
	case ECDSA:
		ecdsapub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.InvalidArgumentError("cannot verify signature with wrong type of public key")
		}

		if len(sig) != 2 {
			return errors.InvalidArgumentError("cannot verify malformed signature")
		}

		sigR := new(big.Int).SetBytes(sig[0].Bytes())
		sigS := new(big.Int).SetBytes(sig[1].Bytes())

		if !ecdsa.Verify(ecdsapub, hashed, sigR, sigS) {
			return errors.SignatureError("ECDSA verification failure")
		}
		return nil
	default:
		return errors.SignatureError("Unsupported public key algorithm used in signature")
	}
}

func (pk publicKey) ParsePrivateKey(data []byte, pub crypto.PublicKey) (crypto.PrivateKey, error) {
	buf := bytes.NewBuffer(data)

	switch pk {
	case RSA, RSASignOnly, RSAEncryptOnly:
		rsaPub := pub.(*rsa.PublicKey)
		rsaPriv := new(rsa.PrivateKey)
		rsaPriv.PublicKey = *rsaPub

		d := new(encoding.MPI)
		if _, err := d.ReadFrom(buf); err != nil {
			return nil, err
		}

		p := new(encoding.MPI)
		if _, err := p.ReadFrom(buf); err != nil {
			return nil, err
		}

		q := new(encoding.MPI)
		if _, err := q.ReadFrom(buf); err != nil {
			return nil, err
		}

		rsaPriv.D = new(big.Int).SetBytes(d.Bytes())
		rsaPriv.Primes = make([]*big.Int, 2)
		rsaPriv.Primes[0] = new(big.Int).SetBytes(p.Bytes())
		rsaPriv.Primes[1] = new(big.Int).SetBytes(q.Bytes())
		if err := rsaPriv.Validate(); err != nil {
			return nil, err
		}
		rsaPriv.Precompute()
		return rsaPriv, nil
	case DSA:
		dsaPub := pub.(*dsa.PublicKey)
		dsaPriv := new(dsa.PrivateKey)
		dsaPriv.PublicKey = *dsaPub

		x := new(encoding.MPI)
		if _, err := x.ReadFrom(buf); err != nil {
			return nil, err
		}

		dsaPriv.X = new(big.Int).SetBytes(x.Bytes())
		return dsaPriv, nil
	case ElGamal:
		egPub := pub.(*elgamal.PublicKey)
		egPriv := new(elgamal.PrivateKey)
		egPriv.PublicKey = *egPub

		x := new(encoding.MPI)
		if _, err := x.ReadFrom(buf); err != nil {
			return nil, err
		}

		egPriv.X = new(big.Int).SetBytes(x.Bytes())
		return egPriv, nil
	case ECDSA:
		ecdsaPub := pub.(*ecdsa.PublicKey)
		ecdsaPriv := new(ecdsa.PrivateKey)
		ecdsaPriv.PublicKey = *ecdsaPub

		d := new(encoding.MPI)
		if _, err := d.ReadFrom(buf); err != nil {
			return nil, err
		}

		ecdsaPriv.D = new(big.Int).SetBytes(d.Bytes())
		return ecdsaPriv, nil
	case ECDH:
		ecdhPub := pub.(*ecdh.PublicKey)
		ecdhPriv := new(ecdh.PrivateKey)
		ecdhPriv.PublicKey = *ecdhPub

		d := new(encoding.MPI)
		if _, err := d.ReadFrom(buf); err != nil {
			return nil, err
		}

		ecdhPriv.D = d.Bytes()
		return ecdhPriv, nil
	}
	panic("impossible")
}

func (pk publicKey) ParsePublicKey(r io.Reader) (crypto.PublicKey, []encoding.Field, error) {
	switch pk {
	case RSA, RSASignOnly, RSAEncryptOnly:
		n := new(encoding.MPI)
		if _, err := n.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		e := new(encoding.MPI)
		if _, err := e.ReadFrom(r); err != nil {
			return nil, nil, err
		}
		if len(e.Bytes()) > 3 {
			return nil, nil, errors.UnsupportedError("large public exponent")
		}

		rsa := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n.Bytes()),
			E: 0,
		}
		for i := 0; i < len(e.Bytes()); i++ {
			rsa.E <<= 8
			rsa.E |= int(e.Bytes()[i])
		}

		return rsa, []encoding.Field{n, e}, nil
	case DSA:
		p := new(encoding.MPI)
		if _, err := p.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		q := new(encoding.MPI)
		if _, err := q.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		g := new(encoding.MPI)
		if _, err := g.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		y := new(encoding.MPI)
		if _, err := y.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		dsa := &dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: new(big.Int).SetBytes(p.Bytes()),
				Q: new(big.Int).SetBytes(q.Bytes()),
				G: new(big.Int).SetBytes(g.Bytes()),
			},
			Y: new(big.Int).SetBytes(y.Bytes()),
		}

		return dsa, []encoding.Field{p, q, g, y}, nil
	case ElGamal:
		p := new(encoding.MPI)
		if _, err := p.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		g := new(encoding.MPI)
		if _, err := g.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		y := new(encoding.MPI)
		if _, err := y.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		elgamal := &elgamal.PublicKey{
			P: new(big.Int).SetBytes(p.Bytes()),
			G: new(big.Int).SetBytes(g.Bytes()),
			Y: new(big.Int).SetBytes(y.Bytes()),
		}

		return elgamal, []encoding.Field{p, g, y}, nil
	case ECDSA:
		oid := new(encoding.BitString)
		if _, err := oid.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		p := new(encoding.MPI)
		if _, err := p.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		var c elliptic.Curve
		if bytes.Equal(oid.Bytes(), oidCurveP256) {
			c = elliptic.P256()
		} else if bytes.Equal(oid.Bytes(), oidCurveP384) {
			c = elliptic.P384()
		} else if bytes.Equal(oid.Bytes(), oidCurveP521) {
			c = elliptic.P521()
		} else {
			return nil, nil, errors.UnsupportedError(fmt.Sprintf("unsupported oid: %x", oid))
		}

		x, y := elliptic.Unmarshal(c, p.Bytes())
		if x == nil {
			return nil, nil, errors.UnsupportedError("failed to parse EC point")
		}

		ecdsa := &ecdsa.PublicKey{
			Curve: c,
			X:     x,
			Y:     y,
		}

		return ecdsa, []encoding.Field{oid, p}, nil
	case ECDH:
		oid := new(encoding.BitString)
		if _, err := oid.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		p := new(encoding.MPI)
		if _, err := p.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		kdf := new(encoding.BitString)
		if _, err := kdf.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		var c elliptic.Curve
		if bytes.Equal(oid.Bytes(), oidCurveP256) {
			c = elliptic.P256()
		} else if bytes.Equal(oid.Bytes(), oidCurveP384) {
			c = elliptic.P384()
		} else if bytes.Equal(oid.Bytes(), oidCurveP521) {
			c = elliptic.P521()
		} else {
			return nil, nil, errors.UnsupportedError(fmt.Sprintf("unsupported oid: %x", oid))
		}

		x, y := elliptic.Unmarshal(c, p.Bytes())
		if x == nil {
			return nil, nil, errors.UnsupportedError("failed to parse EC point")
		}

		ecdh := &ecdh.PublicKey{
			Curve: c,
			X:     x,
			Y:     y,
			KDF:   kdf,
		}

		return ecdh, []encoding.Field{oid, p, kdf}, nil
	default:
		return nil, nil, errors.UnsupportedError("public key type: " + strconv.Itoa(int(pk)))
	}
}

func (pk publicKey) ParseEncryptedKey(r io.Reader) ([]encoding.Field, error) {
	switch pk {
	case RSA, RSAEncryptOnly:
		mpi1 := new(encoding.MPI)
		if _, err := mpi1.ReadFrom(r); err != nil {
			return nil, err
		}
		return []encoding.Field{mpi1}, nil
	case ElGamal:
		mpi1 := new(encoding.MPI)
		if _, err := mpi1.ReadFrom(r); err != nil {
			return nil, err
		}

		mpi2 := new(encoding.MPI)
		if _, err := mpi2.ReadFrom(r); err != nil {
			return nil, err
		}

		return []encoding.Field{mpi1, mpi2}, nil
	case ECDH:
		vsG := new(encoding.MPI)
		if _, err := vsG.ReadFrom(r); err != nil {
			return nil, err
		}

		m := new(encoding.BitString)
		if _, err := m.ReadFrom(r); err != nil {
			return nil, err
		}

		return []encoding.Field{vsG, m}, nil
	default:
		return nil, errors.UnsupportedError("public key type: " + strconv.Itoa(int(pk)))
	}
}

func (pk publicKey) ParseSignature(r io.Reader) ([]encoding.Field, error) {
	switch pk {
	case RSA, RSASignOnly:
		sig := new(encoding.MPI)
		if _, err := sig.ReadFrom(r); err != nil {
			return nil, err
		}
		return []encoding.Field{sig}, nil
	case DSA, ECDSA:
		sigR := new(encoding.MPI)
		if _, err := sigR.ReadFrom(r); err != nil {
			return nil, err
		}

		sigS := new(encoding.MPI)
		if _, err := sigS.ReadFrom(r); err != nil {
			return nil, err
		}

		return []encoding.Field{sigR, sigS}, nil
	default:
		return nil, errors.UnsupportedError("public key type: " + strconv.Itoa(int(pk)))
	}
}

func (pk publicKey) SerializePrivateKey(w io.Writer, priv crypto.PrivateKey) error {
	switch pk {
	case RSA, RSASignOnly, RSAEncryptOnly:
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return errors.InvalidArgumentError("cannot serialize wrong type of private key")
		}

		if _, err := new(encoding.MPI).SetBig(rsaPriv.D).WriteTo(w); err != nil {
			return err
		}
		if _, err := new(encoding.MPI).SetBig(rsaPriv.Primes[1]).WriteTo(w); err != nil {
			return err
		}
		if _, err := new(encoding.MPI).SetBig(rsaPriv.Primes[0]).WriteTo(w); err != nil {
			return err
		}
		_, err := new(encoding.MPI).SetBig(rsaPriv.Precomputed.Qinv).WriteTo(w)
		return err
	case DSA:
		dsaPriv, ok := priv.(*dsa.PrivateKey)
		if !ok {
			return errors.InvalidArgumentError("cannot serialize wrong type of private key")
		}

		_, err := new(encoding.MPI).SetBig(dsaPriv.X).WriteTo(w)
		return err
	case ElGamal:
		egPriv, ok := priv.(*elgamal.PrivateKey)
		if !ok {
			return errors.InvalidArgumentError("cannot serialize wrong type of private key")
		}

		_, err := new(encoding.MPI).SetBig(egPriv.X).WriteTo(w)
		return err
	case ECDSA:
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return errors.InvalidArgumentError("cannot serialize wrong type of private key")
		}

		_, err := new(encoding.MPI).SetBig(ecdsaPriv.D).WriteTo(w)
		return err
	case ECDH:
		ecdhPriv, ok := priv.(*ecdh.PrivateKey)
		if !ok {
			return errors.InvalidArgumentError("cannot serialize wrong type of private key")
		}

		_, err := encoding.NewMPI(ecdhPriv.D).WriteTo(w)
		return err
	default:
		return errors.InvalidArgumentError("unknown private key type")
	}
}

func (pk publicKey) Encode(pub crypto.PublicKey) []encoding.Field {
	switch pk {
	case RSA, RSASignOnly, RSAEncryptOnly:
		rsapub := pub.(*rsa.PublicKey)
		return []encoding.Field{
			new(encoding.MPI).SetBig(rsapub.N),
			new(encoding.MPI).SetBig(big.NewInt(int64(rsapub.E))),
		}
	case DSA:
		dsapub := pub.(*dsa.PublicKey)
		return []encoding.Field{
			new(encoding.MPI).SetBig(dsapub.P),
			new(encoding.MPI).SetBig(dsapub.Q),
			new(encoding.MPI).SetBig(dsapub.G),
			new(encoding.MPI).SetBig(dsapub.Y),
		}
	case ElGamal:
		egpub := pub.(*elgamal.PublicKey)
		return []encoding.Field{
			new(encoding.MPI).SetBig(egpub.P),
			new(encoding.MPI).SetBig(egpub.G),
			new(encoding.MPI).SetBig(egpub.Y),
		}
	case ECDSA:
		ecdsapub := pub.(*ecdsa.PublicKey)

		var oid []byte
		switch ecdsapub.Curve {
		case elliptic.P256():
			oid = oidCurveP256
		case elliptic.P384():
			oid = oidCurveP384
		case elliptic.P521():
			oid = oidCurveP521
		default:
			panic("unknown elliptic curve")
		}

		return []encoding.Field{
			encoding.NewBitString(oid),
			encoding.NewMPI(elliptic.Marshal(ecdsapub.Curve, ecdsapub.X, ecdsapub.Y)),
		}
	default:
		panic("unreachable")
	}
}
