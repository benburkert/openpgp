// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"testing"
	"time"
)

var privateKeyTests = []struct {
	privateKeyHex string
	creationTime  time.Time
}{
	{
		privKeyRSAHex,
		time.Unix(0x4cc349a8, 0),
	},
	{
		privKeyElGamalHex,
		time.Unix(0x4df9ee1a, 0),
	},
	{
		privKeyECDSA256Hex,
		time.Unix(0x56ce9b87, 0),
	},
	{
		privKeyECDSA384Hex,
		time.Unix(0x56ce9ff9, 0),
	},
	{
		privKeyECDSA521Hex,
		time.Unix(0x56cea099, 0),
	},
}

func TestPrivateKeyRead(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		err = privKey.Decrypt([]byte("wrong password"))
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect key", i)
			continue
		}

		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

func TestIssue11505(t *testing.T) {
	// parsing a rsa private key with p or q == 1 used to panic due to a divide by zero
	_, _ = Read(readerFromHex("9c3004303030300100000011303030000000000000010130303030303030303030303030303030303030303030303030303030303030303030303030303030303030"))
}

// Generated with `gpg --export-secret-keys "Test Key 2"`
const privKeyRSAHex = "9501fe044cc349a8010400b70ca0010e98c090008d45d1ee8f9113bd5861fd57b88bacb7c68658747663f1e1a3b5a98f32fda6472373c024b97359cd2efc88ff60f77751adfbf6af5e615e6a1408cfad8bf0cea30b0d5f53aa27ad59089ba9b15b7ebc2777a25d7b436144027e3bcd203909f147d0e332b240cf63d3395f5dfe0df0a6c04e8655af7eacdf0011010001fe0303024a252e7d475fd445607de39a265472aa74a9320ba2dac395faa687e9e0336aeb7e9a7397e511b5afd9dc84557c80ac0f3d4d7bfec5ae16f20d41c8c84a04552a33870b930420e230e179564f6d19bb153145e76c33ae993886c388832b0fa042ddda7f133924f3854481533e0ede31d51278c0519b29abc3bf53da673e13e3e1214b52413d179d7f66deee35cac8eacb060f78379d70ef4af8607e68131ff529439668fc39c9ce6dfef8a5ac234d234802cbfb749a26107db26406213ae5c06d4673253a3cbee1fcbae58d6ab77e38d6e2c0e7c6317c48e054edadb5a40d0d48acb44643d998139a8a66bb820be1f3f80185bc777d14b5954b60effe2448a036d565c6bc0b915fcea518acdd20ab07bc1529f561c58cd044f723109b93f6fd99f876ff891d64306b5d08f48bab59f38695e9109c4dec34013ba3153488ce070268381ba923ee1eb77125b36afcb4347ec3478c8f2735b06ef17351d872e577fa95d0c397c88c71b59629a36aec"

// Generated by `gpg --export-secret-keys` followed by a manual extraction of
// the ElGamal subkey from the packets.
const privKeyElGamalHex = "9d0157044df9ee1a100400eb8e136a58ec39b582629cdadf830bc64e0a94ed8103ca8bb247b27b11b46d1d25297ef4bcc3071785ba0c0bedfe89eabc5287fcc0edf81ab5896c1c8e4b20d27d79813c7aede75320b33eaeeaa586edc00fd1036c10133e6ba0ff277245d0d59d04b2b3421b7244aca5f4a8d870c6f1c1fbff9e1c26699a860b9504f35ca1d700030503fd1ededd3b840795be6d9ccbe3c51ee42e2f39233c432b831ddd9c4e72b7025a819317e47bf94f9ee316d7273b05d5fcf2999c3a681f519b1234bbfa6d359b4752bd9c3f77d6b6456cde152464763414ca130f4e91d91041432f90620fec0e6d6b5116076c2985d5aeaae13be492b9b329efcaf7ee25120159a0a30cd976b42d7afe030302dae7eb80db744d4960c4df930d57e87fe81412eaace9f900e6c839817a614ddb75ba6603b9417c33ea7b6c93967dfa2bcff3fa3c74a5ce2c962db65b03aece14c96cbd0038fc"

// Generated with `gpg2 --export-secret-keys`
const (
	privKeyECDSA256Hex = "94a50456ce9b8713082a8648ce3d03010702030422d99a04c7e49deaf7645a56fe5c2eca06a13dbc84e02f024bb20f9bff40520a1eaea636fa9573642cb61203c635b54ad0233bdc7a0bc066f35fc17468f8f0e8fe07030207e110de909edd95e6b90020678a269dc74841719e57125e2e351c4675e6e1b1173beb0c96d1cf11d284fb51527624c7222a8a7802944b528c7f6eec6699d4837ca5cee22160550d18148f6af0368c"
	privKeyECDSA384Hex = "94d20456ce9ff913052b81040022030304bbd188b5018325fbdf1c491bf8e7ead419246bcfc1d0b88161bd3dd64039e5a00afbc56865d8309228d3e9f66567084e5e908c4dc33aa6d8ea914af2ebc117e905dae03288d4bd12050cfd48f5a1f89711c3150692a55b5ddac0149bc758e19dfe070302a0a6bba01d6bfb34e6aae45f44f142acef49e6b46837adcf00ecd9f6a5035c1f6ce41ef0f404e3c22bd0ecd14c4878e19ba8cee510c0b5372c04241ddfba45858ccc25f3ffe21c8c2d1cead8f883146957bde2984bc8b741bbf9a02f000e56"
	privKeyECDSA521Hex = "96000001080456cea09913052b8104002304230401e63fd4ef1398f0d57e42991c32f25e30bd5cb9dce3409d0de1c7a32d2e866bc3e557e6fc6f92013bb332f7df5b778c9c0a58a20fef0404ac2c488453336c9c8cad009e93771ee6b195a102b82171b07ccd06a2eb8ce8ce82c22200dbc513c16fb3aaf68809859efd19d64297ba19d28b83f038c566ca6a2a28bd3ee27275b909593504fe070302cc8e587938576e8be615d4d7e4c25c60c418a0a87e3e547d8cb674cdde722a192e69b20d444f1182613717c544db8f628f432a9016e0c5190b11d75a898ab3fa91cd74c1866a0553de7aa4997b8561c8b13b4c0b420d5c6328927ddb30b89c8b41daba767a158f26cd856a116cbcd5a2a0"
)
