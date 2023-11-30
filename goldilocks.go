package goldilocks

//#cgo CFLAGS: -I./goldilocks
//#cgo LDFLAGS: -lgoldilocks
//#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/build/darwin-x86_64
//#cgo darwin,arm64 LDFLAGS:-L${SRCDIR}/build/darwin-arm64
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

// UTILS

func IsZerosBuffer(buffer []byte) bool {
	for _, b := range buffer {
		if b != 0 {
			return false
		}
	}
	return true
}

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

	// public -> C
	ed := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	C.memcpy(unsafe.Pointer(&ed[0]), unsafe.Pointer(&edKey[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

	// retrieve x448
	x := [C.GOLDILOCKS_X448_PUBLIC_BYTES]C.uint8_t{}
	C.goldilocks_ed448_convert_public_key_to_x448(&x[0], &ed[0])

	// x448 -> golang
	golangX448Key := [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte{}
	C.memcpy(unsafe.Pointer(&golangX448Key[0]), unsafe.Pointer(&x[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)

	return golangX448Key
}

func EdPrivateKeyToX448(edKey PrivateKey) [C.GOLDILOCKS_X448_PRIVATE_BYTES]byte {
	if len(edKey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong len")
	}

	// private -> C
	ed := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	C.memcpy(unsafe.Pointer(&ed[0]), unsafe.Pointer(&edKey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	// retrieve x448
	x := [C.GOLDILOCKS_X448_PRIVATE_BYTES]C.uint8_t{}
	C.goldilocks_ed448_convert_private_key_to_x448(&x[0], &ed[0])

	// x448 -> golang
	golangX448Key := [C.GOLDILOCKS_X448_PRIVATE_BYTES]byte{}
	C.memcpy(unsafe.Pointer(&golangX448Key[0]), unsafe.Pointer(&x[0]), C.GOLDILOCKS_X448_PRIVATE_BYTES)

	// Erasing temporary values of private keys
	edZero := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{0}
	C.memcpy(unsafe.Pointer(&ed[0]), unsafe.Pointer(&edZero[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)
	xZero := [C.GOLDILOCKS_X448_PRIVATE_BYTES]C.uint8_t{0}
	C.memcpy(unsafe.Pointer(&x[0]), unsafe.Pointer(&xZero[0]), C.GOLDILOCKS_X448_PRIVATE_BYTES)

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

	// x448Pub from public
	x448Pub := EdPublicKeyToX448(pubkey)

	// x448Priv -> C
	cX448Priv := [C.GOLDILOCKS_X448_PRIVATE_BYTES]C.uint8_t{}
	C.memcpy(unsafe.Pointer(&cX448Priv[0]), unsafe.Pointer(&x448Priv[0]), C.GOLDILOCKS_X448_PRIVATE_BYTES)

	// x448Pub -> C
	cX448Pub := [C.GOLDILOCKS_X448_PUBLIC_BYTES]C.uint8_t{}
	C.memcpy(unsafe.Pointer(&cX448Pub[0]), unsafe.Pointer(&x448Pub[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)

	// retrieve common secret
	cSecret := [C.GOLDILOCKS_X448_PUBLIC_BYTES]C.uint8_t{}
	C.goldilocks_x448(&cSecret[0], &cX448Pub[0], &cX448Priv[0])

	// common secret -> golang
	secret := [C.GOLDILOCKS_X448_PUBLIC_BYTES]byte{}
	C.memcpy(unsafe.Pointer(&secret[0]), unsafe.Pointer(&cSecret[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)

	// Erasing temporary values of private keys
	xZero := [C.GOLDILOCKS_X448_PRIVATE_BYTES]C.uint8_t{0}
	C.memcpy(unsafe.Pointer(&cX448Priv[0]), unsafe.Pointer(&xZero[0]), C.GOLDILOCKS_X448_PRIVATE_BYTES)
	C.memcpy(unsafe.Pointer(&x448Priv[0]), unsafe.Pointer(&xZero[0]), C.GOLDILOCKS_X448_PRIVATE_BYTES)
	sZero := [C.GOLDILOCKS_X448_PUBLIC_BYTES]C.uint8_t{0}
	C.memcpy(unsafe.Pointer(&cX448Pub[0]), unsafe.Pointer(&sZero[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)
	C.memcpy(unsafe.Pointer(&cSecret[0]), unsafe.Pointer(&sZero[0]), C.GOLDILOCKS_X448_PUBLIC_BYTES)

	return secret
}

// PRIVATE, SECRET AND PUBLIC

func PrivateToSecret(privkey PrivateKey) PrivateKey {

	if len(privkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong extkey len")
	}

	// private -> C
	cPriv := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	C.memcpy(unsafe.Pointer(&cPriv[0]), unsafe.Pointer(&privkey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	// retrieve secret
	cSec := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	C.goldilocks_ed448_private_to_secretkey(&cSec[0], &cPriv[0])

	// secret -> golang
	var secretkey PrivateKey
	C.memcpy(unsafe.Pointer(&secretkey[0]), unsafe.Pointer(&cSec[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	// Erasing temporary values of private keys
	pZero := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{0}
	C.memcpy(unsafe.Pointer(&cPriv[0]), unsafe.Pointer(&pZero[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)
	C.memcpy(unsafe.Pointer(&cSec[0]), unsafe.Pointer(&pZero[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	return secretkey
}

func SecretToPublic(secretkey PrivateKey) PublicKey {

	if len(secretkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong extkey len")
	}

	// secret -> C
	cSec := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	C.memcpy(unsafe.Pointer(&cSec[0]), unsafe.Pointer(&secretkey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	// Clamp
	cSec[0] &= 0xfc
	cSec[57-1] = 0
	cSec[57-2] |= 0x80

	// retrieve public
	cPub := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	C.goldilocks_ed448_derive_public_key_from_secretkey(&cPub[0], &cSec[0])

	// public -> golang
	var pubkey PublicKey
	C.memcpy(unsafe.Pointer(&pubkey[0]), unsafe.Pointer(&cPub[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

	// Erasing temporary values of private keys
	sZero := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{0}
	C.memcpy(unsafe.Pointer(&cSec[0]), unsafe.Pointer(&sZero[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	return pubkey
}

func PrivateToPublic(privkey PrivateKey) PublicKey {

	if len(privkey) != C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES {
		panic("wrong extkey len")
	}

	// private -> C
	cPriv := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	C.memcpy(unsafe.Pointer(&cPriv[0]), unsafe.Pointer(&privkey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

	// retrieve public
	cPub := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	C.goldilocks_ed448_derive_public_key(&cPub[0], &cPriv[0])

	// public -> golang
	var pubkey PublicKey
	C.memcpy(unsafe.Pointer(&pubkey[0]), unsafe.Pointer(&cPub[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

	// Erasing temporary values of private keys
	pZero := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{0}
	C.memcpy(unsafe.Pointer(&cPriv[0]), unsafe.Pointer(&pZero[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

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

// TODO try golang array to func
func SignWithPrivate(privkey PrivateKey, pubkey PublicKey, message, context []byte, prehashed bool) [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]byte {
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
	C.goldilocks_ed448_sign(&cSig[0], &cPriv[0], &cPub[0], hash, C.size_t(len(message)), C.uchar(cPrehashed), ctx, C.uchar(len(context)))

	C.memcpy(unsafe.Pointer(&signature[0]), unsafe.Pointer(&cSig[0]), C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES)

	// Erasing temporary values of private keys
	pZero := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{0}
	C.memcpy(unsafe.Pointer(&cPriv[0]), unsafe.Pointer(&pZero[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

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
	context := []byte{}
	prehashed := false

	cSec := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	cNon := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	cPub := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	cSig := [C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES]C.uint8_t{}

	cMessage := make([]C.uint8_t, len(message))
	cContext := make([]C.uint8_t, len(context))

	var cPrehashed uint8
	if prehashed {
		cPrehashed = 1
	}

	C.memcpy(unsafe.Pointer(&cSec[0]), unsafe.Pointer(&secretkey[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)
	C.memcpy(unsafe.Pointer(&cNon[0]), unsafe.Pointer(&nonce[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)
	C.memcpy(unsafe.Pointer(&cPub[0]), unsafe.Pointer(&pubkey[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

	// Clamp secret
	cSec[0] &= 0xfc
	cSec[57-1] = 0
	cSec[57-2] |= 0x80

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
	C.goldilocks_ed448_sign_with_secretkey_and_prenonce(&cSig[0], &cSec[0], &cNon[0], &cPub[0], hash, C.size_t(len(message)), C.uchar(cPrehashed), ctx, C.uchar(len(context)))
	C.memcpy(unsafe.Pointer(&signature[0]), unsafe.Pointer(&cSig[0]), C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES)

	// Erasing temporary values of private keys
	sZero := [C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES]C.uint8_t{}
	C.memcpy(unsafe.Pointer(&cSec[0]), unsafe.Pointer(&sZero[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)
	C.memcpy(unsafe.Pointer(&cNon[0]), unsafe.Pointer(&sZero[0]), C.GOLDILOCKS_EDDSA_448_PRIVATE_BYTES)

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

	if IsZerosBuffer(signature[:]) || IsZerosBuffer(pubkey[:]) {
		return false
	}

	C.memcpy(unsafe.Pointer(&cSig[0]), unsafe.Pointer(&signature[0]), C.GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES)
	C.memcpy(unsafe.Pointer(&cPub[0]), unsafe.Pointer(&pubkey[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

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
	success = C.goldilocks_ed448_verify(&cSig[0], &cPub[0], hash, C.size_t(len(message)), C.uchar(cPrehashed), ctx, C.uchar(len(context)))
	if success == -1 {
		return true
	}
	return false
}

// ADD TWO PUBLIC KEYS (FOR HDwallet)

func AddTwoPublic(pub1 PublicKey, pub2 PublicKey) PublicKey {

	var pub PublicKey

	if len(pub1) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong extkey len")
	}
	if len(pub2) != C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES {
		panic("wrong extkey len")
	}

	cPub1 := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	cPub2 := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}
	cPub := [C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES]C.uint8_t{}

	C.memcpy(unsafe.Pointer(&cPub1[0]), unsafe.Pointer(&pub1[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)
	C.memcpy(unsafe.Pointer(&cPub2[0]), unsafe.Pointer(&pub2[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)

	// TODO Handle errors in libgoldilocks when unable to deserialize
	C.goldilocks_ed448_add_two_publickeys(&cPub[0], &cPub1[0], &cPub2[0])

	C.memcpy(unsafe.Pointer(&pub[0]), unsafe.Pointer(&cPub[0]), C.GOLDILOCKS_EDDSA_448_PUBLIC_BYTES)
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
