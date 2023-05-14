package pkg

import (
	"errors"
	"finalbruh/pkg/address"
	"finalbruh/pkg/peer"
	"finalbruh/pkg/proto"
	"finalbruh/pkg/utils"
	"fmt"
	"golang.org/x/net/context"
	"time"
)

func (n *Node) peerCheck(addr string) error {
	if n.PeerDb.Get(addr) == nil {
		return errors.New("request from non-peered node")
	}
	err := n.PeerDb.UpdateLastSeen(addr, uint32(time.Now().UnixNano()))
	if err != nil {
		fmt.Printf("ERROR {Node.peerCheck}: error" +
			"when calling updatelastseen.\n")
	}
	return nil
}

func (n *Node) Version(ctx context.Context, in *proto.VersionRequest) (*proto.Empty, error) {
	if int(in.Version) != n.Conf.Version {
		return &proto.Empty{}, nil
	}
	newAddr := address.New(in.AddrMe, uint32(time.Now().UnixNano()))
	if n.AddrDb.Get(newAddr.Addr) != nil {
		err := n.AddrDb.UpdateLastSeen(newAddr.Addr, newAddr.LastSeen)
		if err != nil {
			return &proto.Empty{}, nil
		}
	} else if err := n.AddrDb.Add(newAddr); err != nil {
		return &proto.Empty{}, nil
	}
	key, _ := utils.DecodePublicKey(in.SerPk)
	newPeer := peer.New(n.AddrDb.Get(newAddr.Addr), in.Version, key)
	pendingVer := newPeer.Addr.SentVer != time.Time{} && newPeer.Addr.SentVer.Add(n.Conf.VerTimeout).After(time.Now())
	if n.PeerDb.Add(newPeer) && !pendingVer {
		newPeer.Addr.SentVer = time.Now()
		kk, _ := utils.EncodePublicKey(&n.Id.PrivateKey.PublicKey)
		_, err := newAddr.VersionRPC(&proto.VersionRequest{
			Version: uint32(n.Conf.Version),
			AddrYou: in.AddrMe,
			AddrMe:  n.Addr,
			SerPk:   kk,
		})
		if err != nil {
			return &proto.Empty{}, err
		}
	}
	return &proto.Empty{}, nil
}

func (n *Node) SendAddresses(ctx context.Context, in *proto.Addresses) (*proto.Empty, error) {
	foundNew := false
	for _, addr := range in.Addrs {
		if addr.Addr == n.Addr {
			continue
		}
		newAddr := address.New(addr.Addr, addr.LastSeen)
		if p := n.PeerDb.Get(addr.Addr); p != nil {
			if p.Addr.LastSeen < addr.LastSeen {
				err := n.PeerDb.UpdateLastSeen(addr.Addr, addr.LastSeen)
				if err != nil {
					fmt.Printf("ERROR {Node.SendAddresses}: error" +
						"when calling updatelastseen.\n")
				}
				foundNew = true
			}
		} else if a := n.AddrDb.Get(addr.Addr); a != nil {
			if a.LastSeen < addr.LastSeen {
				err := n.AddrDb.UpdateLastSeen(addr.Addr, addr.LastSeen)
				if err != nil {
					fmt.Printf("ERROR {Node.SendAddresses}: error" +
						"when calling updatelastseen.\n")
				}
			}
		} else {
			err := n.AddrDb.Add(newAddr)
			if err == nil {
				foundNew = true
			}
		}
		go func() {
			_, err := newAddr.VersionRPC(&proto.VersionRequest{
				Version: uint32(n.Conf.Version),
				AddrYou: newAddr.Addr,
				AddrMe:  n.Addr,
			})
			if err != nil {
				utils.Debug.Printf("%v recieved no response from VersionRPC to %v",
					utils.FmtAddr(n.Addr), utils.FmtAddr(addr.Addr))
			}
		}()
	}
	if foundNew {
		bcPeers := n.PeerDb.GetRandom(2, []string{n.Addr})
		for _, p := range bcPeers {
			_, err := p.Addr.SendAddressesRPC(in)
			if err != nil {
				utils.Debug.Printf("%v recieved no response from SendAddressesRPC to %v",
					utils.FmtAddr(n.Addr), utils.FmtAddr(p.Addr.Addr))
			}
		}
	}
	return &proto.Empty{}, nil
}

func (n *Node) GetAddresses(ctx context.Context, in *proto.Empty) (*proto.Addresses, error) {
	utils.Debug.Printf("Node {%v} received a GetAddresses req from the network.\n",
		n.Addr)
	return &proto.Addresses{Addrs: n.AddrDb.Serialize()}, nil
}

func (n *Node) Register(ctx context.Context, in *proto.Registration) (*proto.Certificate, error) {
	signa, err := utils.Sign(n.Id.PrivateKey, in.Register)
	if err != nil {
		utils.Err.Printf("%v received error trying to make certificate",
			utils.FmtAddr(n.Addr))
	}
	c := Certificate{Certificate: signa}
	return c.Serialize(), nil
}

func (n *Node) AddMember(ctx context.Context, in *proto.EncKeysMem) (*proto.Empty, error) {
	stuff, err := utils.PubDecrypt(n.Id.PrivateKey, in.Encryptedstuff)
	if err != nil {
		utils.Err.Printf("%v received error trying to decrypt add member message",
			utils.FmtAddr(n.Addr))
	}
	gc, err := GCDeserialize(stuff)
	if err != nil {
		utils.Err.Printf("%v received error trying to decode add member message",
			utils.FmtAddr(n.Addr))
	}
	m := make(map[string]bool)
	for _, item := range n.Group.Members {
		m[item.Addr.Addr] = true
	}
	var diff []string
	for _, item := range gc.Members {
		if _, ok := m[item]; !ok && item != n.Addr {
			diff = append(diff, item)
		}
	}
	for _, mem := range diff {
		if mem != n.Addr {
			n.ConnectToPeer(mem)
		}
	}
	time.Sleep(1 * time.Second)
	for _, mem := range diff {
		for _, p := range n.PeerDb.List() {
			if p.Addr.Addr == mem {
				n.Group.AddMember(p)
			}
		}
	}
	n.Group.ReplaceKeys(gc.Key)
	for _, mem := range diff {
		utils.Debug.Printf("%v added %v",
			utils.FmtAddr(n.Addr), utils.FmtAddr(mem))
	}
	return &proto.Empty{}, nil
}

func (n *Node) KickMember(ctx context.Context, in *proto.EncKeysMem) (*proto.Empty, error) {
	stuff, err := utils.PubDecrypt(n.Id.PrivateKey, in.Encryptedstuff)
	if err != nil {
		utils.Err.Printf("%v received error trying to decrypt kick member message",
			utils.FmtAddr(n.Addr))
	}
	gc, err := GCDeserialize(stuff)
	if err != nil {
		utils.Err.Printf("%v received error trying to decode kick member message",
			utils.FmtAddr(n.Addr))
	}
	n.Group.KickMyMember(gc.Members[0])
	n.Group.ReplaceKeys(gc.Key)
	utils.Debug.Printf("%v received kick msg and kicked %v",
		utils.FmtAddr(n.Addr), utils.FmtAddr(gc.Members[0]))
	return &proto.Empty{}, nil
}

func (n *Node) GroupMessage(ctx context.Context, in *proto.GroupIM) (*proto.Empty, error) {
	plain, err := utils.SymDecrypt(n.Group.GCM, in.Encryptedmsg)
	if err != nil {
		utils.Err.Printf("%v received error trying to decrypt message",
			utils.FmtAddr(n.Addr))
	}
	utils.Debug.Printf("%v received message %v",
		utils.FmtAddr(n.Addr), plain)
	return &proto.Empty{}, nil
}
