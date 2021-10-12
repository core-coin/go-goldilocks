package goldilocks

//#cgo CFLAGS: -I./goldilocks
//#cgo LDFLAGS: -lgoldilocks
//#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/build/darwin-x86_64
//#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/build/linux-x86_64
//#cgo linux,arm64 LDFLAGS:-L${SRCDIR}/build/linux-arm64
//#cgo windows,amd64 LDFLAGS:-L${SRCDIR}/build/windows-x86_64
//#include "ed448.h"
//#include "point_448.h"
//#include <stdio.h>
//#include <string.h>
import "C"
import (
	"fmt"
	"io"
	"unsafe"
)

type PublicKey [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]byte
type PrivateKey [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]byte

// SLICES TO KEYS

func BytesToPublicKey(key []byte) (pk PublicKey) {
	if len(key) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		return PublicKey{}
	}
	copy(pk[:], key)
	return
}

// Use it only for tests please
func BytesToPrivateKey(key []byte) (pk PrivateKey) {
	if len(key) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		return PrivateKey{}
	}
	copy(pk[:], key)
	return
}

// DIFFIE-HELLMAN SHARED SECRET

func EdPublicKeyToX448(edKey PublicKey) [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte {
	if len(edKey) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong len")
	}
	golangX448Key := [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte{}
	C.goldilocks_ed448_convert_public_key_to_x448((*C.uint8_t)(unsafe.Pointer(&golangX448Key[0])), (*C.uint8_t)(unsafe.Pointer(&edKey[0])))

	return golangX448Key
}

func EdPrivateKeyToX448(edKey PrivateKey) [C.GOLDILOCKS_X448_PRIVATE_BYTES]byte {
	if len(edKey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong len")
	}

	golangX448Key := [C.GOLDILOCKS_X448_PRIVATE_BYTES]byte{}
	C.goldilocks_ed448_convert_private_key_to_x448((*C.uint8_t)(unsafe.Pointer(&golangX448Key[0])), (*C.uint8_t)(unsafe.Pointer(&edKey[0])))

	return golangX448Key
}

func Ed448DeriveSecret(pubkey PublicKey, privkey PrivateKey) [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte {
	if len(privkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong privkey len")
	}
	if len(pubkey) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong pubkey len")
	}

	// x448Priv from private or secret key
	var x448Priv = [56]byte{0}
	if privkey[57-1]&0x80 == 0x00 {
		x448Priv = EdPrivateKeyToX448(privkey)
	} else {
		copy(x448Priv[:], privkey[0:56])
	}
	x448Pub := EdPublicKeyToX448(pubkey)
	secret := [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte{}

	C.goldilocks_x448((*C.uint8_t)(unsafe.Pointer(&secret[0])), (*C.uint8_t)(unsafe.Pointer(&x448Pub[0])), (*C.uint8_t)(unsafe.Pointer(&x448Priv[0])))

	return secret
}

// PRIVATE, SECRET AND PUBLIC

func PrivateToSecret(privkey PrivateKey) PrivateKey {

	if len(privkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong extkey len")
	}
	var secretkey PrivateKey
	C.goldilocks_ed448_private_to_secretkey((*C.uint8_t)(unsafe.Pointer(&secretkey[0])), (*C.uint8_t)(unsafe.Pointer(&privkey[0])))
	secretkey[56] |= 0x80

	return secretkey
}

func SecretToPublic(secretkey PrivateKey) PublicKey {

	if len(secretkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong extkey len")
	}

	// Clamp
	var cSec PrivateKey
	copy(cSec[:], secretkey[:])
	cSec[0] &= 0xfc
	cSec[57-1] = 0
	cSec[57-2] |= 0x80

	var pubkey PublicKey
	C.goldilocks_ed448_derive_public_key_from_secretkey((*C.uint8_t)(unsafe.Pointer(&pubkey[0])), (*C.uint8_t)(unsafe.Pointer(&cSec[0])))

	// Erasing temporary values of private keys
	Zero := PrivateKey{0}
	copy(cSec[:], Zero[:])

	return pubkey
}


func PrivateToPublic(privkey PrivateKey) PublicKey {

	if len(privkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong extkey len")
	}
	var pubkey PublicKey

	C.goldilocks_ed448_derive_public_key((*C.uint8_t)(unsafe.Pointer(&pubkey[0])), (*C.uint8_t)(unsafe.Pointer(&privkey[0])))

	return pubkey
}

func Ed448DerivePublicKey(privkey PrivateKey) PublicKey {

	if privkey[57-1]&0x80 == 0x00 {
		return PrivateToPublic(privkey)
	} else {
		return SecretToPublic(privkey)
	}
}

// CREATE SIGNATURE

//TODO try golang array to func
func SignWithPrivate(privkey PrivateKey, pubkey PublicKey, message, context []byte, prehashed bool) [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]byte {
	
	signature := [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]byte{}


	cMessage := make([]C.uint8_t, len(message))
	cContext := make([]C.uint8_t, len(context))

	var cPrehashed uint8
	if prehashed {
		cPrehashed = 1
	}

	if len(privkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong privkey len")
	}

	if len(pubkey) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong pubkey len")
	}

	var ctx *C.uint8_t
	if context != nil && len(context) > 0 {
		C.memcpy(unsafe.Pointer(&cContext[0]), unsafe.Pointer(&context[0]), C.size_t(len(context)))
		ctx = &cContext[0]
	} else {
		zero := [1]C.uint8_t{}
		ctx = &zero[0]
	}
	var hash *C.uint8_t
	if message != nil && len(message) > 0 {
		C.memcpy(unsafe.Pointer(&cMessage[0]), unsafe.Pointer(&message[0]), C.size_t(len(message)))
		hash = &cMessage[0]
	} else {
		zero := [1]C.uint8_t{}
		hash = &zero[0]
	}
	C.goldilocks_ed448_sign((*C.uint8_t)(unsafe.Pointer(&signature[0])), (*C.uint8_t)(unsafe.Pointer(&privkey[0])), (*C.uint8_t)(unsafe.Pointer(&pubkey[0])), hash, C.size_t(len(message)), C.uchar(cPrehashed), ctx, C.uchar(len(context)))

	return signature
}

func SignSecretAndNonce(secretkey PrivateKey, nonce PrivateKey, pubkey PublicKey, message []byte) [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]byte {

	if len(secretkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong extkey len")
	}
	if len(nonce) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong nonce len")
	}
	if len(pubkey) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong pubkey len")
	}

	signature := [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]byte{}
	zero := [1]C.uint8_t{}

	cMessage := make([]C.uint8_t, len(message))

	var cPrehashed uint8

	var cSec PrivateKey
	copy(cSec[:], secretkey[:])
	cSec[0] &= 0xfc
	cSec[57-1] = 0
	cSec[57-2] |= 0x80

	var hash *C.uint8_t
	if message != nil && len(message) > 0 {
		C.memcpy(unsafe.Pointer(&cMessage[0]), unsafe.Pointer(&message[0]), C.size_t(len(message)))
		hash = &cMessage[0]
	} else {
		hash = &zero[0]
	}
	C.goldilocks_ed448_sign_with_secretkey_and_prenonce((*C.uint8_t)(unsafe.Pointer(&signature[0])), (*C.uint8_t)(unsafe.Pointer(&cSec[0])), (*C.uint8_t)(unsafe.Pointer(&nonce[0])), (*C.uint8_t)(unsafe.Pointer(&pubkey[0])), hash, C.size_t(len(message)), C.uchar(cPrehashed), &zero[0], C.uchar(0))

	// Erasing temporary values of private keys
	Zero := PrivateKey{0}
	copy(cSec[:], Zero[:])

	return signature
}

func Ed448Sign(privkey PrivateKey, pubkey PublicKey, message, context []byte, prehashed bool) [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]byte {

	if privkey[57-1]&0x80 == 0x00 {
		return SignWithPrivate(privkey, pubkey, message, context, prehashed)
	} else {
		if len(context) != 0 {
			panic("Context is not supported!")
		}
		if prehashed {
			panic("Prehashing is not supported!")
		}
		var sk PrivateKey
		copy(sk[:], privkey[:])
		sk[0] &= 0xfc
		sk[57-1] = 0
		sk[57-2] |= 0x80

		sig := SignSecretAndNonce(sk, sk, pubkey, message)

		// Erasing temporary values of private keys
		var sZero = PrivateKey{0}
		copy(sk[:], sZero[:])
		
		return sig
	}
}


// VERIFY SIGNATURE

func Ed448Verify(pubkey PublicKey, signature, message, context []byte, prehashed bool) bool {

	cMessage := make([]C.uint8_t, len(message))
	cContext := make([]C.uint8_t, len(context))

	var cPrehashed uint8
	if prehashed {
		cPrehashed = 1
	}

	if len(signature) != C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES {
		panic("wrong signature len")
	}

	if len(pubkey) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong pubkey len")
	}

	var success C.goldilocks_error_t

	var ctx *C.uint8_t
	if context != nil && len(context) > 0 {
		C.memcpy(unsafe.Pointer(&cContext[0]), unsafe.Pointer(&context[0]), C.size_t(len(context)))
		ctx = &cContext[0]
	} else {
		zero := [1]C.uint8_t{}
		ctx = &zero[0]
	}
	var hash *C.uint8_t
	if message != nil && len(message) > 0 {
		C.memcpy(unsafe.Pointer(&cMessage[0]), unsafe.Pointer(&message[0]), C.size_t(len(message)))
		hash = &cMessage[0]
	} else {
		zero := [1]C.uint8_t{}
		hash = &zero[0]
	}
	success = C.goldilocks_ed448_verify((*C.uint8_t)(unsafe.Pointer(&signature[0])), (*C.uint8_t)(unsafe.Pointer(&pubkey[0])), hash, C.size_t(len(message)), C.uchar(cPrehashed), ctx, C.uchar(len(context)))
	if success == -1 {
		return true
	}
	return false
}

// ADD TWO PUBLIC KEYS (FOR HDwallet)

func AddTwoPublic(pub1 PublicKey, pub2 PublicKey) PublicKey {

	if len(pub1) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong extkey len")
	}
	if len(pub2) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong extkey len")
	}
	
	var pub PublicKey
	// TODO Handle errors in libgoldilocks when unable to deserialize
	C.goldilocks_ed448_add_two_publickeys((*C.uint8_t)(unsafe.Pointer(&pub[0])), (*C.uint8_t)(unsafe.Pointer(&pub1[0])), (*C.uint8_t)(unsafe.Pointer(&pub2[0])))

	return pub
}

// GENERATE PRIVATE KEY

func Ed448GenerateKey(reader io.Reader) (PrivateKey, error) {
	key := new(PrivateKey)
	n, err := io.ReadFull(reader, key[:])
	if err != nil {
		return PrivateKey{}, err
	} else if n != 57 {
		return PrivateKey{}, fmt.Errorf("not 57 random bytes")
	}
	key[56] &= 0x7f
	return *key, nil
}

/* 	How to use */
/*
func main() {
	testKey := "b93a28627cfa29fedb03c21aac0faa1ea0ba84c10cefa07c938f2e0adbf996f02c8d00e39695dfb6a0636c8bcb21645b06a869dfbbb489ef00"
	//golangHexEdKey := "6ada368e2799a55b9eb0e41e711d22af2569cf838656049635ba0ae4f344e180ce0e6b8f753df6d9de8aaf7ded0c8f61d93d4f29810098b780"
	//fmt.Println("Golang Ed Hex Key", golangHexEdKey)

	golangEdKey := common.Hex2Bytes(testKey)
	//fmt.Println("Golang Ed Key", golangEdKey)
	golangX448Key := EdPublicKeyToX448(BytesToPublicKey(golangEdKey))

	fmt.Println("Golang X448 Key", golangX448Key)

	fmt.Println("Golang X448 Hex Key", common.Bytes2Hex(golangX448Key[:]))

	golangPrivHexEdKey := "bd6cf469833692c5bf9bb68b8fdb9a0a4c70b01c2162eaceec3c669ccbdcabfe01eee57fe1ad942c98e840b4bf87ad05d3d5db9d794e029955"
	//fmt.Println("Golang Private Ed Hex Key", golangPrivHexEdKey)

	golangPrivEdKey := common.Hex2Bytes(golangPrivHexEdKey)
	//fmt.Println("Golang Private Ed Key", golangPrivEdKey)

	golangPrivX448Key := EdPrivateKeyToX448(BytesToPrivateKey(golangPrivEdKey))

	fmt.Println("Golang Private X448 Key", golangPrivX448Key)

	fmt.Println("Golang Private X448 Hex Key", common.Bytes2Hex(golangPrivX448Key[:]))

	sig := Ed448Sign(BytesToPrivateKey(golangPrivEdKey), BytesToPublicKey(golangEdKey), []byte{1}, []byte{1}, true)
	fmt.Println(sig)
	//sig[0] = 0x1
	fmt.Println("verify: ", Ed448Verify(BytesToPublicKey(golangEdKey), sig[:],  []byte{1}, []byte{1}, false))

	derivedKey := Ed448DerivePublicKey(BytesToPrivateKey(golangPrivEdKey))
	//fmt.Println("primary pub", golangHexEdKey)
	fmt.Println("derived", common.Bytes2Hex(derivedKey[:]))

	hash := sha3.NewLegacyKeccak512()
	timeB, err := time.Now().MarshalBinary()
	_, err = hash.Write(timeB)
	asd, err := Ed448GenerateKey(rand.Reader)
	fmt.Println(asd, "err", err, len(asd))


	asdd := Ed448DeriveSecret(BytesToPublicKey(golangEdKey), BytesToPrivateKey(golangPrivEdKey))
	fmt.Println(asdd)
	fmt.Println(len(asdd))
}
*/
