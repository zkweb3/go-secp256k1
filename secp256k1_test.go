package secp256k1

import (
	"crypto/ecdsa"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	secp_eth "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
)

const (
	sk      string = "0x5d7da1c2a925ea9c454c120806360428e91756b98d4ade2bef09fd924c02e803" // test private key
	message string = "hello"                                                              // test message
)

func TestSign(t *testing.T) {
	skECDSA, err := crypto.HexToECDSA(strings.TrimPrefix(sk, "0x"))
	require.Nil(t, err)
	hash := crypto.Keccak256Hash([]byte(message))
	r, s, err := SignRFC6979(skECDSA, hash)
	require.Nil(t, err)
	// verify result
	pub := skECDSA.Public()
	pubECDSA, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, ecdsa.Verify(pubECDSA, hash.Bytes(), r, s))
	// print result
	fmt.Println("r", r.Text(16))
	fmt.Println("s", s.Text(16))
}

func TestGetPublicKey(t *testing.T) {
	skECDSA, err := crypto.HexToECDSA(strings.TrimPrefix(sk, "0x"))
	require.Nil(t, err)
	r, err := GetPublicKey(skECDSA)
	require.Nil(t, err)
	// verify result
	pub := skECDSA.Public()
	pubECDSA, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, pubECDSA.Equal(r))
	// print result
	fmt.Println("pub.x", r.X.Text(16))
	fmt.Println("pub.y", r.Y.Text(16))
}

func TestScalarMult(t *testing.T) {
	skECDSA, err := crypto.HexToECDSA(strings.TrimPrefix(sk, "0x"))
	require.Nil(t, err)
	curve := secp_eth.S256()
	x, y, err := ScalarMult(skECDSA, curve.Gx, curve.Gy)
	require.Nil(t, err)
	// verify result
	require.True(t, curve.IsOnCurve(x, y))
	// print result
	fmt.Println("curve.x", x.Text(16))
	fmt.Println("curve.y", y.Text(16))
}
