package addressdb

import (
	"finalbruh/pkg/address"
	"finalbruh/pkg/proto"
)

type AddressDb interface {
	Add(*address.Address) error
	Get(string) *address.Address
	UpdateLastSeen(string, uint32) error
	List() []*address.Address
	Serialize() []*proto.Address
}

func New(eph bool, limit int) AddressDb {
	return &EphemeralAddressDb{addresses: make(map[string]*address.Address), limit: limit}
}
