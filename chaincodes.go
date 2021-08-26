package goldilocks

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

type MasterExtended [114]uint8
type SecretExtended [114]uint8
type PublicExtended [114]uint8

func SHA512Hash(password, salt []uint8) []uint8 {

	return pbkdf2.Key(password, salt, 1, 57, sha3.New512)

}

func concatenateAndHex(prefix uint8, key []uint8, index uint32, salt []uint8) []uint8 {

	var p [62]uint8
	p[0] = prefix

	copy(p[1:58], key[:])

	for i := 58; i < 62; i++ {
		p[i] = uint8(index)
		index >>= 8
	}

	return SHA512Hash(p[:], salt)
}

func addTwoSecrets(secKey1 []uint8, secKey2 []uint8) []uint8 {

	if len(secKey1) != 57 {
		panic("wrong slice length")
	}
	if len(secKey2) != 57 {
		panic("wrong slice length")
	}

	var secKey [57]uint8
	var count uint16
	count = 0
	for i := 0; i < 57; i++ {
		count += uint16(secKey1[i]) + uint16(secKey2[i])
		secKey[i] = uint8(count)
		count >>= 8
	}
	return secKey[:]
}

func clampTemplate(t []uint8) {

	if len(t) != 57 {
		panic("wrong slice length")
	}

	t[56] = 0
	t[55] = 0
	t[54] = 0
	t[53] = 0
	t[0] &= 0xfc
}

func (m MasterExtended) deriveSecretExtended() SecretExtended {
	var s SecretExtended
	copy(s[:57], m[:57])
	var privkey PrivateKey
	copy(privkey[:], m[57:])
	var secret SecretKey = Ed448PrivateKeyToSecret(privkey)
	copy(s[57:], secret[:])

	var zero [57]uint8
	copy(privkey[:], zero[:])
	copy(secret[:], zero[:])

	return s
}

func (s SecretExtended) derivePublic() PublicKey {
	var secret SecretKey
	copy(secret[:], s[57:])
	var public PublicKey = Ed448DerivePublicKeyFromSecret(secret)

	var zero [57]uint8
	copy(secret[:], zero[:])

	return public
}

func (s SecretExtended) derivePublicExtended() PublicExtended {
	var pubExtended PublicExtended
	copy(pubExtended[:57], s[:57])
	p := s.derivePublic()
	copy(pubExtended[57:], p[:])
	return pubExtended
}

func (s SecretExtended) generateChildSecret(index uint32) SecretExtended {
	var child SecretExtended

	if index >= 0x80000000 {
		hex := concatenateAndHex(1, s[57:], index, s[:57])
		copy(child[:57], hex[:])

		var zero [57]uint8
		copy(hex[:], zero[:])

		hex = concatenateAndHex(0, s[57:], index, s[:57])
		clampTemplate(hex)
		var a []uint8 = addTwoSecrets(s[57:], hex)
		copy(child[57:], a[:])

		copy(hex[:], zero[:])
		copy(a[:], zero[:])

		return child
	} else {
		var pub PublicKey = s.derivePublic()
		hex := concatenateAndHex(3, pub[:], index, s[:57])
		copy(child[:57], hex[:])

		var zero [57]uint8
		copy(hex[:], zero[:])

		hex = concatenateAndHex(2, pub[:], index, s[:57])
		clampTemplate(hex)
		var a []uint8 = addTwoSecrets(s[57:], hex)
		copy(child[57:], a[:])

		copy(hex[:], zero[:])
		copy(a[:], zero[:])

		return child
	}
}

func (s SecretExtended) generateChildPublic(index uint32) PublicExtended {
	var s1 SecretExtended = s.generateChildSecret(index)
	var p PublicExtended = s1.derivePublicExtended()
	var zero [114]uint8
	copy(s1[:], zero[:])
	return p
}

func (pub PublicExtended) generateChildPublic(index uint32) PublicExtended {
	if index >= 0x80000000 {
		panic("wrong index value")
	}
	var child PublicExtended

	hex := concatenateAndHex(3, pub[57:], index, pub[:57])
	copy(child[:57], hex[:])

	hex = concatenateAndHex(2, pub[57:], index, pub[:57])
	clampTemplate(hex)

	var a1 PublicKey
	var s1 SecretKey
	copy(a1[:], pub[57:])
	copy(s1[:], hex[:])
	a2 := Ed448DerivePublicKeyFromSecret(s1)
	var a PublicKey = Ed448AddTwoPublicKeys(a1, a2)
	copy(child[57:], a[:])

	return child
}

func SignWithExtendedKey(secret SecretExtended, message, context []uint8, prehashed bool) [114]uint8 {
	var s, t SecretKey
	copy(s[:], secret[57:])
	seed := SHA512Hash(secret[57:], secret[:57])
	copy(t[:], seed[:])
	sig := Ed448SignWithSecretAndNonce(s, t, secret.derivePublic(), message, context, prehashed)
	return sig
}

/*
func main() {
	hex := "9f667aa751981e6407d5f1fe6b68c4092b6ef55d1176782c3c74eeeacb4b53e611c4ad827e42c48ce6fe69cc139a131f17b0a712e1f2f8440239c69dcda6ee7c273b8f6b4c853c2a7a1e1aa22968e75ae6c357c01cb4c0ed939c040057a2c833cf9c8a5ebd66b165826ce1ea3c7af8bdac3a"
	var mkey MasterExtended
	copy(mkey[:], common.Hex2Bytes(hex)[:])
	secret := mkey.deriveSecretExtended()
	fmt.Printf("Secret Extended Key: \"%x\"\n", secret[:])
	public := secret.derivePublicExtended()
	fmt.Printf("Secret Public Key: \"%x\"\n\n", public[:])

	childPublic1 := secret.generateChildPublic(0)
	fmt.Printf("Child Secret -> Public: \"%x\"\n", childPublic1[:])
	childPublic2 := public.generateChildPublic(0)
	fmt.Printf("Child Public -> Public: \"%x\"\n\n", childPublic2[:])

	fox := []byte("The quick brown fox jumps over the lazy dog")
	sig := SignWithExtendedKey(secret, fox, []byte{1}, true)
	fmt.Printf("Signature: \"%x\"\n", sig[:])
	fmt.Println("Verify:", Ed448Verify(secret.derivePublic(), sig[:], fox, []byte{1}, true))

	var p PrivateKey
	p[0] = 1
	fmt.Println(p)
	pubKey := Ed448DerivePublicKey(p)
	fmt.Println(Ed448Sign(p, pubKey, fox, []byte{}, false))

}
*/