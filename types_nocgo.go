//go:build nacl || js || !cgo

package goldilocks

type PublicKey [57]byte
type PrivateKey [57]byte
