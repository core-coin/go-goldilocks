# Go-goldilocks

## Golang Ed448-Goldilocks bindings

## How to use

```go
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
```
