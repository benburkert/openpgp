# openpgp

A fork of golang.org/x/crypto/openpgp with added support for:

* ECDH encrypt/decrypt (rfc 6637)
* Private/Experimental public key, secret key, & hash algorithms (or any other unassigned algorithm identifier)
* Private/Experimental S2K algorithms
* Encrypted S2K serialization
* [GnuPG EdDSA, gnu-dummy, & divert-to-card extensions](https://github.com/benburkert/gnupg)
