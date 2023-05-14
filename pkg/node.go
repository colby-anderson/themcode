package pkg

import (
	"encoding/json"
	"finalbruh/pkg/address"
	"finalbruh/pkg/address/addressdb"
	"finalbruh/pkg/group"
	"finalbruh/pkg/id"
	"finalbruh/pkg/peer"
	"finalbruh/pkg/proto"
	"finalbruh/pkg/utils"
	"fmt"
	"google.golang.org/grpc"
	"net"
	"os"
	"time"
)

type Node struct {
	*proto.UnimplementedBrunoCoinServer
	Server *grpc.Server

	Conf *Config
	Addr string
	Id   *id.ID

	fGetAddr bool

	AddrDb addressdb.AddressDb
	PeerDb peer.PeerDb

	Group group.Group

	Paused bool
}

func New(conf *Config) *Node {
	n := &Node{Conf: conf}
	ident, err := id.New()
	if err == nil {
		n.Id = ident
	}

	n.AddrDb = addressdb.New(true, 1000)
	n.PeerDb = peer.NewDb(true, 200, "")

	return n
}

func (n *Node) Start() {
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	addr := fmt.Sprintf("%v:%v", hostname, n.Conf.Port)
	n.Addr = addr
	n.PeerDb.SetAddr(addr)
	utils.Debug.Printf("%v started", utils.FmtAddr(n.Addr))
	n.StartServer(addr)
}

func (n *Node) NewGroup() {
	n.Group = group.New()
}

func (n *Node) AddAMember(addr string) {
	if n.PeerDb.In(addr) {
		n.Group.AddMember(n.PeerDb.Get(addr))
		utils.Debug.Printf("%v added member %v",
			utils.FmtAddr(n.Addr), utils.FmtAddr(addr))
		n.Group.GenerateNewKeys()
		for _, p := range n.Group.Members {
			signa, err := utils.Sign(n.Id.PrivateKey, n.Group.Key)
			//_, err := utils.Sign(n.Id.PrivateKey, n.Group.Key)
			if err != nil {
				utils.Err.Printf("%v received error when signing new group key",
					utils.FmtAddr(n.Addr))
			}
			membies := n.Group.GetMembers()
			membies = append(membies, n.Addr)
			gcc := GroupChange{n.Id.Certificate, membies, n.Group.Key, signa}
			//gcc := GroupChange{"", n.Group.GetMembers(), n.Group.Key, ""}
			kk, err := utils.PubEncrypt(p.PublicKey, gcc.Serialize()) // TODO: broken
			if err != nil {
				utils.Err.Printf("%v received error when encrypting with public key",
					utils.FmtAddr(n.Addr))
			}
			go func(addr *address.Address, msg string) {
				_, err := addr.AddMemberRPC(&proto.EncKeysMem{Encryptedstuff: msg})
				if err != nil {
					utils.Err.Printf("%v received error when sending add message to %v",
						utils.FmtAddr(n.Addr), utils.FmtAddr(addr.Addr))
				}
			}(p.Addr, kk)
		}
	} else {
		utils.Err.Printf("%v cannot register via %v without being connected to him",
			utils.FmtAddr(n.Addr), utils.FmtAddr(addr))
	}
}

func (n *Node) KickAMember(addr string) {
	if n.PeerDb.In(addr) {
		n.Group.KickMember(n.PeerDb.Get(addr))
		utils.Debug.Printf("%v kicked member %v",
			utils.FmtAddr(n.Addr), utils.FmtAddr(addr))
		n.Group.GenerateNewKeys()
		for _, p := range n.Group.Members {
			signa, err := utils.Sign(n.Id.PrivateKey, n.Group.Key)
			//_, err := utils.Sign(n.Id.PrivateKey, n.Group.Key)
			if err != nil {
				utils.Err.Printf("%v received error when signing new group key",
					utils.FmtAddr(n.Addr))
			}
			gcc := GroupChange{n.Id.Certificate, []string{addr}, n.Group.Key, signa}
			//gcc := GroupChange{"", []string{addr}, n.Group.Key, ""}
			kk, err := utils.PubEncrypt(p.PublicKey, gcc.Serialize())
			if err != nil {
				utils.Err.Printf("%v received error when encrypting with public key",
					utils.FmtAddr(n.Addr))
			}
			go func(addr *address.Address, msg string) {
				_, err := addr.KickMemberRPC(&proto.EncKeysMem{Encryptedstuff: msg})
				if err != nil {
					utils.Err.Printf("%v received error when sending kick message to %v",
						utils.FmtAddr(n.Addr), utils.FmtAddr(addr.Addr))
				}
			}(p.Addr, kk)
		}
	} else {
		utils.Err.Printf("%v cannot register via %v without being connected to him",
			utils.FmtAddr(n.Addr), utils.FmtAddr(addr))
	}
}

func (n *Node) MessageMyGroup(message string) {
	for _, p := range n.Group.Members {
		kk := utils.SymEncrypt(n.Group.GCM, message)
		go func(addr *address.Address, msg string) {
			_, err := addr.GroupMessageRPC(&proto.GroupIM{Encryptedmsg: msg})
			if err != nil {
				utils.Err.Printf("%v received error when sending %v to %v",
					utils.FmtAddr(n.Addr), message, utils.FmtAddr(addr.Addr))
			} else {
				utils.Debug.Printf("%v sent encrypted version of %v as %v to all",
					utils.FmtAddr(n.Addr), message, kk)
			}
		}(p.Addr, kk)
	}
}

func (n *Node) LeaveMyGroup() {
	n.Group.KickMyMember(n.Addr)
	utils.Debug.Printf("%v successfully left group", utils.FmtAddr(n.Addr))
	n.Group.GenerateNewKeys()
	for _, p := range n.Group.Members {
		signa, err := utils.Sign(n.Id.PrivateKey, n.Group.Key)
		//_, err := utils.Sign(n.Id.PrivateKey, n.Group.Key)
		if err != nil {
			utils.Err.Printf("%v received error when signing new group key",
				utils.FmtAddr(n.Addr))
		}
		gcc := GroupChange{n.Id.Certificate, []string{n.Addr}, n.Group.Key, signa}
		//gcc := GroupChange{"", []string{addr}, n.Group.Key, ""}
		kk, err := utils.PubEncrypt(p.PublicKey, gcc.Serialize())
		if err != nil {
			utils.Err.Printf("%v received error when encrypting with public key",
				utils.FmtAddr(n.Addr))
		}
		go func(addr *address.Address, msg string) {
			_, err := addr.KickMemberRPC(&proto.EncKeysMem{Encryptedstuff: msg})
			if err != nil {
				utils.Err.Printf("%v received error when sending kick message to %v",
					utils.FmtAddr(n.Addr), utils.FmtAddr(addr.Addr))
			}
		}(p.Addr, kk)
	}
}

func (n *Node) RegisterWithCA(addr string) {
	if n.PeerDb.In(addr) {
		p := n.PeerDb.Get(addr)
		encodedPK, err := utils.EncodePublicKey(&n.Id.PrivateKey.PublicKey)
		if err != nil {
			utils.Err.Printf("%v received error when trying to encode public key",
				utils.FmtAddr(n.Addr))
		}
		go func(myAddr string, theirAddr *address.Address, pk string) {
			cert, err := theirAddr.RegisterRPC(&proto.Registration{Register: pk})
			if err != nil {
				utils.Err.Printf("%v received error when registering with CA %v",
					utils.FmtAddr(n.Addr), utils.FmtAddr(theirAddr.Addr))
			} else if !utils.Verify(p.PublicKey, pk, cert.Cert) {
				utils.Debug.Printf("%v received incorrect certificate from  %v",
					utils.FmtAddr(myAddr), utils.FmtAddr(theirAddr.Addr))
			} else {
				n.Id.Certificate = cert.Cert
				utils.Debug.Printf("%v received valid certificate from %v",
					utils.FmtAddr(myAddr), utils.FmtAddr(theirAddr.Addr))
			}
		}(n.Addr, p.Addr, encodedPK)
	} else {
		utils.Err.Printf("%v cannot register via CA %v without being connected to him",
			utils.FmtAddr(n.Addr), utils.FmtAddr(addr))
	}
}

func (n *Node) ConnectToPeer(addr string) {
	a := address.New(addr, 0)
	key, _ := utils.EncodePublicKey(&n.Id.PrivateKey.PublicKey)
	_, err := a.VersionRPC(&proto.VersionRequest{
		Version: uint32(n.Conf.Version),
		AddrYou: addr,
		AddrMe:  n.Addr,
		SerPk:   key,
	})
	if err != nil {
		utils.Debug.Printf("%v recieved no response from VersionRPC to %v",
			utils.FmtAddr(n.Addr), utils.FmtAddr(addr))
	}
}

func (n *Node) BroadcastAddr() {
	myAddr := proto.Address{Addr: n.Addr, LastSeen: uint32(time.Now().UnixNano())}
	for _, p := range n.PeerDb.List() {
		go func(addr *address.Address) {
			_, err := addr.SendAddressesRPC(&proto.Addresses{Addrs: []*proto.Address{&myAddr}})
			if err != nil {
				utils.Debug.Printf("%v recieved no response from SendAddressesRPC to %v",
					utils.FmtAddr(n.Addr), utils.FmtAddr(p.Addr.Addr))
			}
		}(p.Addr)
	}
}

func (n *Node) StartServer(addr string) {
	lis, err := net.Listen("tcp4", addr)
	if err != nil {
		panic(err)
	}
	// Open node to connections
	n.Server = grpc.NewServer()
	proto.RegisterBrunoCoinServer(n.Server, n)
	go func() {
		err := n.Server.Serve(lis)
		if err != nil {
			fmt.Printf("ERROR {Node.StartServer}: error" +
				"when trying to serve server")
		}
	}()
}

func (n *Node) PauseNetwork() {
	n.Server.Stop()
	utils.Debug.Printf("%v paused", utils.FmtAddr(n.Addr))
}

func (n *Node) ResumeNetwork() {
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	addr := fmt.Sprintf("%v:%v", hostname, n.Conf.Port)
	n.StartServer(addr)
	utils.Debug.Printf("%v resumed", utils.FmtAddr(n.Addr))
}

func (n *Node) Kill() {
	n.Server.GracefulStop()
}

type Registration struct {
	Register string
}

func (r *Registration) Serialize() *proto.Registration {
	return &proto.Registration{
		Register: r.Register,
	}
}

type Certificate struct {
	Certificate string
}

func (c *Certificate) Serialize() *proto.Certificate {
	return &proto.Certificate{
		Cert: c.Certificate,
	}
}

type GroupChange struct {
	Certificate string
	Members     []string
	Key         string
	SigOverKey  string
}

func (c *GroupChange) Serialize() string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(b)
}

func GCDeserialize(c string) (*GroupChange, error) {
	var gc GroupChange
	err := json.Unmarshal([]byte(c), &gc)
	if err != nil {
		return nil, err
	}
	return &gc, nil
}
