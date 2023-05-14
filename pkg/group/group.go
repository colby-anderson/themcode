package group

import (
	"crypto/cipher"
	"finalbruh/pkg/peer"
	"finalbruh/pkg/utils"
)

type Group struct {
	Members []*peer.Peer
	Key     string
	GCM     cipher.AEAD
}

func New() Group {
	return Group{}
}

func (g *Group) ReplaceKeys(key string) {
	gcm, err := utils.GenerateFromSymKey(key)
	if err != nil {
		utils.Err.Printf("Cannot successfully generate sym key")
	}
	g.GCM = gcm
	g.Key = key
}

func (g *Group) GenerateNewKeys() {
	key, gcm, err := utils.GenerateSymKey()
	if err != nil {
		utils.Err.Printf("Cannot successfully generate sym key")
	}
	g.Key = key
	g.GCM = gcm
}

func (g *Group) GetMembers() []string {
	var newSlice []string
	for _, val := range g.Members {
		newSlice = append(newSlice, val.Addr.Addr)
	}
	return newSlice
}

func (g *Group) AddMember(p *peer.Peer) {
	for _, existingPeer := range g.Members {
		if existingPeer.Addr.Addr == p.Addr.Addr {
			// Peer is already in the group
			return
		}
	}
	// Peer is not in the group, so append it
	g.Members = append(g.Members, p)
}

func (g *Group) KickMember(p *peer.Peer) {
	var newSlice []*peer.Peer
	for _, val := range g.Members {
		if val.Addr.Addr != p.Addr.Addr {
			newSlice = append(newSlice, val)
		}
	}
	g.Members = newSlice
}

func (g *Group) KickMyMember(addr string) {
	var newSlice []*peer.Peer
	for _, val := range g.Members {
		if val.Addr.Addr != addr {
			newSlice = append(newSlice, val)
		}
	}
	g.Members = newSlice
}
