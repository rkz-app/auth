package base_auth

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
)

type AddressGenerator interface {
	GenerateAddressFromPublicKey(publicKey []byte) (string, error)
}

type DoubleSha3AddressGenerator struct {
}

func NewDoubleSha3AddressGenerator() *DoubleSha3AddressGenerator {
	return &DoubleSha3AddressGenerator{}
}

func (d DoubleSha3AddressGenerator) GenerateAddressFromPublicKey(publicKey []byte) (string, error) {
	hash := sha3.New256()
	hash.Write(publicKey)
	iteration1 := hash.Sum(nil)

	secondHash := sha3.New256()
	secondHash.Write(iteration1)
	addressBytes := secondHash.Sum(nil)

	addressHex := hex.EncodeToString(addressBytes)
	return addressHex, nil
}
