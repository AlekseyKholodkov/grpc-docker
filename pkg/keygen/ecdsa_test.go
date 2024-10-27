package keygen

import (
	"crypto/elliptic"
	"fmt"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	result, err := generateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)
}

func TestWriteKeysToFile(t *testing.T) {
	GenerateKeys()
}
