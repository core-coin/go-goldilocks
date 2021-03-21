package goldilocks

import "C"

//#cgo CFLAGS: -I./goldilocks
//#cgo LDFLAGS: -lgoldilocks -lstdc++
//#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/build/darwin-x86_64 -lm
//#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/build/linux-x86_64 -lm
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

func BytesToPublicKey(key []byte) (pk PublicKey) {
	if len(key) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		return PublicKey{}
	}
	copy(pk[:], key)
	return
}

func BytesToPrivateKey(key []byte) (pk PrivateKey) {
	if len(key) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		return PrivateKey{}
	}
	copy(pk[:], key)
	return
}

func EdPublicKeyToX448(edKey PublicKey) [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte {
	if len(edKey) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong len")
	}

	ed := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	x := [C.GOLDILOCKS_X448_PUBLIC_BYTES]C.uint8_t{}

	C.memcpy(unsafe.Pointer(&ed[0]), unsafe.Pointer(&edKey[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

	C.goldilocks_ed448_convert_public_key_to_x448(&x[0], &ed[0])

	golangX448Key := [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte{}
	C.memcpy(unsafe.Pointer(&golangX448Key[0]), unsafe.Pointer(&x[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)

	return golangX448Key
}

func EdPrivateKeyToX448(edKey PrivateKey) [C.GOLDILOCKS_X448_PRIVATE_BYTES]byte {
	if len(edKey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong len")
	}

	ed := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	x := [C.GOLDILOCKS_X448_PRIVATE_BYTES]C.uint8_t{}

	C.memcpy(unsafe.Pointer(&ed[0]), unsafe.Pointer(&edKey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	C.goldilocks_ed448_convert_private_key_to_x448(&x[0], &ed[0])

	golangX448Key := [C.GOLDILOCKS_X448_PRIVATE_BYTES]byte{}
	C.memcpy(unsafe.Pointer(&golangX448Key[0]), unsafe.Pointer(&x[0]), C.GOLDILOCKS_X448_PRIVATE_BYTES)

	return golangX448Key
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

	var success C.goldilocks_error_t

	var ctx *C.uint8_t
	if context != nil && len(context) > 0 {
		C.memcpy(unsafe.Pointer(&cContext[0]), unsafe.Pointer(&context[0]), C.ulong(len(context)))
		ctx = &cContext[0]
	} else {
		zero := [1]C.uint8_t{}
		ctx = &zero[0]
	}
	var hash *C.uint8_t
	if message != nil && len(message) > 0 {
		C.memcpy(unsafe.Pointer(&cMessage[0]), unsafe.Pointer(&message[0]), C.ulong(len(message)))
		hash = &cMessage[0]
	} else {
		zero := [1]C.uint8_t{}
		hash = &zero[0]
	}
	success = C.goldilocks_ed448_verify(&cSig[0], &cPub[0], hash, C.ulong(len(message)), C.uchar(cPrehashed), ctx, C.uchar(len(context)))

	if success == -1 {
		return true
	}
	return false
}

func Ed448DeriveSecret(pubkey PublicKey, privkey PrivateKey) [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte {
	if len(privkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong privkey len")
	}

	if len(pubkey) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong pubkey len")
	}

	x448Priv := EdPrivateKeyToX448(privkey)
	x448Pub := EdPublicKeyToX448(pubkey)
	secret := [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte{}

	cX448Priv := [C.GOLDILOCKS_X448_PRIVATE_BYTES]C.uint8_t{}
	cX448Pub := [C.GOLDILOCKS_X448_PUBLIC_BYTES]C.uint8_t{}
	cSecret := [C.GOLDILOCKS_X448_PUBLIC_BYTES]C.uint8_t{}

	C.memcpy(unsafe.Pointer(&cX448Priv[0]), unsafe.Pointer(&x448Priv[0]), C.GOLDILOCKS_X448_PRIVATE_BYTES)
	C.memcpy(unsafe.Pointer(&cX448Pub[0]), unsafe.Pointer(&x448Pub[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)

	C.goldilocks_x448(&cSecret[0], &cX448Pub[0], &cX448Priv[0])

	C.memcpy(unsafe.Pointer(&secret[0]), unsafe.Pointer(&cSecret[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)

	return secret
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

	var ctx *C.uint8_t
	if context != nil && len(context) > 0 {
		C.memcpy(unsafe.Pointer(&cContext[0]), unsafe.Pointer(&context[0]), C.ulong(len(context)))
		ctx = &cContext[0]
	} else {
		zero := [1]C.uint8_t{}
		ctx = &zero[0]
	}
	var hash *C.uint8_t
	if message != nil && len(message) > 0 {
		C.memcpy(unsafe.Pointer(&cMessage[0]), unsafe.Pointer(&message[0]), C.ulong(len(message)))
		hash = &cMessage[0]
	} else {
		zero := [1]C.uint8_t{}
		hash = &zero[0]
	}
	C.goldilocks_ed448_sign(&cSig[0], &cPriv[0], &cPub[0], hash, C.ulong(len(message)), C.uchar(cPrehashed), ctx, C.uchar(len(context)))

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

func Ed448GenerateKey(reader io.Reader) (PrivateKey, error) {
	key := new(PrivateKey)
	n, err := io.ReadFull(reader, key[:])
	if err != nil {
		return PrivateKey{}, err
	} else if n != 57 {
		return PrivateKey{}, fmt.Errorf("not 57 random bytes")
	}
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
