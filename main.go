package goldilocks

import "C"

//#cgo CFLAGS: -I./goldilocks
//#cgo LDFLAGS: -lgoldilocks -lstdc++
//#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/build/linux-x86_64 -lm
//#include "ed448.h"
//#include <stdio.h>
//#include <string.h>
import "C"
import (
	"fmt"
	"github.com/core-coin/gofortuna/fortuna"
	"unsafe"
)

type PublicKey [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]byte
type PrivateKey [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]byte

func EdPublicKeyToX448(edKey []byte) []byte {
	if len(edKey) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong len")
	}

	ed := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	x := [C.GOLDILOCKS_X448_PUBLIC_BYTES]C.uint8_t{}

	C.memcpy(unsafe.Pointer(&ed[0]), unsafe.Pointer(&edKey[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

	C.goldilocks_ed448_convert_public_key_to_x448(&x[0], &ed[0])

	golangX448Key := [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte{}
	C.memcpy(unsafe.Pointer(&golangX448Key[0]), unsafe.Pointer(&x[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)

	return golangX448Key[:]
}

func EdPrivateKeyToX448(edKey []byte) []byte {
	if len(edKey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong len")
	}

	ed := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	x := [C.GOLDILOCKS_X448_PRIVATE_BYTES]C.uint8_t{}

	C.memcpy(unsafe.Pointer(&ed[0]), unsafe.Pointer(&edKey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	C.goldilocks_ed448_convert_private_key_to_x448(&x[0], &ed[0])

	golangX448Key := [C.GOLDILOCKS_X448_PRIVATE_BYTES]byte{}
	C.memcpy(unsafe.Pointer(&golangX448Key[0]), unsafe.Pointer(&x[0]), C.GOLDILOCKS_X448_PRIVATE_BYTES)

	return golangX448Key[:]
}

func Ed448Verify(pubkey PublicKey, signature, message, context []byte, prehashed bool) bool {
	cSig := [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]C.uint8_t{}
	cPub := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}

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

	C.memcpy(unsafe.Pointer(&cSig[0]), unsafe.Pointer(&signature[0]), C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES)
	C.memcpy(unsafe.Pointer(&cPub[0]), unsafe.Pointer(&pubkey[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)
	C.memcpy(unsafe.Pointer(&cMessage[0]), unsafe.Pointer(&message[0]), C.ulong(len(message)))

	var success C.goldilocks_error_t
	if context != nil && len(context) > 0 {
		C.memcpy(unsafe.Pointer(&cContext[0]), unsafe.Pointer(&context[0]), C.ulong(len(context)))
		success = C.goldilocks_ed448_verify(&cSig[0], &cPub[0], &cMessage[0], C.ulong(len(message)), C.uchar(cPrehashed), &cContext[0], C.uchar(len(context)))
	} else {
		success = C.goldilocks_ed448_verify(&cSig[0], &cPub[0], &cMessage[0], C.ulong(len(message)), C.uchar(cPrehashed), &cPub[0], C.uchar(0))
	}
	if success == -1 {
		return true
	}
	return false
}

func Ed448DeriveSecret() {
	panic("TODO")
}

//TODO try golang array to func
func Ed448Sign(privkey PrivateKey, pubkey PublicKey, message, context []byte, prehashed bool) [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]byte {
	signature := [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]byte{}

	cPriv := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	cPub := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	cSig := [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]C.uint8_t{}

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

	C.memcpy(unsafe.Pointer(&cPriv[0]), unsafe.Pointer(&privkey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)
	C.memcpy(unsafe.Pointer(&cPub[0]), unsafe.Pointer(&pubkey[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)
	C.memcpy(unsafe.Pointer(&cMessage[0]), unsafe.Pointer(&message[0]), C.ulong(len(message)))
	if context != nil && len(context) > 0 {
		C.memcpy(unsafe.Pointer(&cContext[0]), unsafe.Pointer(&context[0]), C.ulong(len(context)))
		C.goldilocks_ed448_sign(&cSig[0], &cPriv[0], &cPub[0], &cMessage[0], C.ulong(len(message)), C.uchar(cPrehashed), &cContext[0], C.uchar(len(context)))
	} else {
		C.goldilocks_ed448_sign(&cSig[0], &cPriv[0], &cPub[0], &cMessage[0], C.ulong(len(message)), C.uchar(cPrehashed), &cPub[0], C.uchar(0))
	}

	C.memcpy(unsafe.Pointer(&signature[0]), unsafe.Pointer(&cSig[0]), C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES)

	return signature
}

func Ed448DerivePublicKey(privkey PrivateKey) PublicKey {
	pubkey := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]byte{}

	cPriv := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	cPub := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}

	C.memcpy(unsafe.Pointer(&cPriv[0]), unsafe.Pointer(&privkey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	C.goldilocks_ed448_derive_public_key(&cPub[0], &cPriv[0])

	C.memcpy(unsafe.Pointer(&pubkey[0]), unsafe.Pointer(&cPub[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

	return pubkey
}

func Ed448GenerateKey(seed []byte) (PrivateKey, error) {
	key := new(PrivateKey)
	if len(seed) != fortuna.SeedFileLength {
		return PrivateKey{}, fortuna.ErrInvalidSeed
	}
	f, err := fortuna.FromBytesSeed(seed)
	if err != nil {
		return PrivateKey{}, err
	}
	n, err := f.Read(key[:])
	if err != nil {
		return PrivateKey{}, err
	} else if n != 57 {
		return PrivateKey{}, fmt.Errorf("not 57 random bytes")
	}
	return *key, nil
}

/* 	How to use

testKey := "b93a28627cfa29fedb03c21aac0faa1ea0ba84c10cefa07c938f2e0adbf996f02c8d00e39695dfb6a0636c8bcb21645b06a869dfbbb489ef00"
//golangHexEdKey := "6ada368e2799a55b9eb0e41e711d22af2569cf838656049635ba0ae4f344e180ce0e6b8f753df6d9de8aaf7ded0c8f61d93d4f29810098b780"
//fmt.Println("Golang Ed Hex Key", golangHexEdKey)

golangEdKey := common.Hex2Bytes(testKey)
//fmt.Println("Golang Ed Key", golangEdKey)

golangX448Key := EdPublicKeyToX448(golangEdKey)

fmt.Println("Golang X448 Key", golangX448Key)

fmt.Println("Golang X448 Hex Key", common.Bytes2Hex(golangX448Key[:]))

golangPrivHexEdKey := "bd6cf469833692c5bf9bb68b8fdb9a0a4c70b01c2162eaceec3c669ccbdcabfe01eee57fe1ad942c98e840b4bf87ad05d3d5db9d794e029955"
//fmt.Println("Golang Private Ed Hex Key", golangPrivHexEdKey)

golangPrivEdKey := common.Hex2Bytes(golangPrivHexEdKey)
//fmt.Println("Golang Private Ed Key", golangPrivEdKey)

golangPrivX448Key := EdPrivateKeyToX448(golangPrivEdKey)

fmt.Println("Golang Private X448 Key", golangPrivX448Key)

fmt.Println("Golang Private X448 Hex Key", common.Bytes2Hex(golangPrivX448Key[:]))

sig := Ed448Sign(golangPrivEdKey, golangEdKey, []byte{1}, []byte{1}, true)
fmt.Println(sig)
//sig[0] = 0x1
fmt.Println("verify: ", Ed448Verify(sig[:], golangEdKey, []byte{1}, []byte{1}, false))

derivedKey := Ed448DerivePublicKey(golangPrivEdKey)
//fmt.Println("primary pub", golangHexEdKey)
fmt.Println("derived", common.Bytes2Hex(derivedKey[:]))

hash := sha3.NewLegacyKeccak512()
timeB, err := time.Now().MarshalBinary()
_, err = hash.Write(timeB)
asd, err := Ed448GenerateKey(hash.Sum(nil))
fmt.Println(asd, "err", err)
*/
