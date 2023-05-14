package id

import (
	"crypto/rsa"
	"finalbruh/pkg/utils"
)

type ID struct {
	PrivateKey  *rsa.PrivateKey
	Certificate string
}

func New() (*ID, error) {
	sk, err := utils.GenerateAsymKey()
	if err != nil {
		return nil, err
	}
	id := &ID{
		PrivateKey: sk,
	}
	return id, nil
}
