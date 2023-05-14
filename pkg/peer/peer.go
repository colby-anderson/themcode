package peer

import (
	"crypto/rsa"
	"finalbruh/pkg/address"
)

type Peer struct {
	Addr      *address.Address
	Version   uint32
	PublicKey *rsa.PublicKey
}

func New(addr *address.Address, version uint32, pk *rsa.PublicKey) *Peer {
	return &Peer{Addr: addr, Version: version, PublicKey: pk}
}
