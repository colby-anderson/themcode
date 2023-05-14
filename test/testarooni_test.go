package test

import (
	"finalbruh/pkg"
	"finalbruh/pkg/utils"
	"testing"
	"time"
)

func TestBasicSystem(t *testing.T) {
	utils.SetDebug(true)

	CAnode := pkg.New(pkg.DefaultConfig(GetFreePort()))
	node1 := pkg.New(pkg.DefaultConfig(GetFreePort()))
	node2 := pkg.New(pkg.DefaultConfig(GetFreePort()))
	node3 := pkg.New(pkg.DefaultConfig(GetFreePort()))
	node4 := pkg.New(pkg.DefaultConfig(GetFreePort()))

	CAnode.Start()
	node1.Start()
	node2.Start()
	node3.Start()
	node4.Start()

	node1.ConnectToPeer(CAnode.Addr)
	node2.ConnectToPeer(CAnode.Addr)
	node3.ConnectToPeer(CAnode.Addr)
	node4.ConnectToPeer(CAnode.Addr)

	// Sleep to give time for all nodes to connect
	time.Sleep(3 * time.Second)

	// Register all nodes
	node1.RegisterWithCA(CAnode.Addr)
	node2.RegisterWithCA(CAnode.Addr)
	node3.RegisterWithCA(CAnode.Addr)
	node4.RegisterWithCA(CAnode.Addr)

	// sleep for time to register
	time.Sleep(3 * time.Second)

	node1.NewGroup()

	node1.ConnectToPeer(node2.Addr)
	node1.ConnectToPeer(node3.Addr)
	node1.ConnectToPeer(node4.Addr)

	// sleep for time to connect
	time.Sleep(3 * time.Second)

	node1.AddAMember(node2.Addr)
	time.Sleep(3 * time.Second)
	node1.AddAMember(node3.Addr)
	time.Sleep(3 * time.Second)
	node1.AddAMember(node4.Addr)
	time.Sleep(3 * time.Second)

	node1.MessageMyGroup("hello")
	time.Sleep(3 * time.Second)
	node2.MessageMyGroup("hi")

	// sleep for time to send
	time.Sleep(5 * time.Second)

	node1.KickAMember(node4.Addr)

	// sleep for time to kick
	time.Sleep(5 * time.Second)

	node1.MessageMyGroup("howdy")

	// sleep for time to send
	time.Sleep(5 * time.Second)

	node3.LeaveMyGroup()

	// sleep for time to leave
	time.Sleep(5 * time.Second)

	node1.MessageMyGroup("good morning")

	// sleep for time to send
	time.Sleep(3 * time.Second)
}
