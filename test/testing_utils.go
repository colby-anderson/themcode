package test

import (
	"finalbruh/pkg"
	"github.com/phayes/freeport"
	"log"
	"testing"
)

func GetFreePort() int {
	port, err := freeport.GetFreePort()
	if err != nil {
		log.Fatal(err)
	}
	return port
}

func ChkNdPrs(t *testing.T, n *pkg.Node, prs []*pkg.Node) {
	for _, pr := range prs {
		if !n.PeerDb.In(pr.Addr) {
			t.Errorf("Node didn't contain peer")
		}
	}
}
