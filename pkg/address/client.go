package address

import (
	"finalbruh/pkg/proto"
	"fmt"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"time"
)

const RPCTimeout = 2 * time.Second

func clientUnaryInterceptor(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	ctx, cancel := context.WithTimeout(ctx, RPCTimeout)
	defer cancel()
	return invoker(ctx, method, req, reply, cc, opts...)
}

func connectToServer(addr string) (*grpc.ClientConn, error) {
	return grpc.Dial(addr, []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithUnaryInterceptor(clientUnaryInterceptor),
	}...)
}

func (a *Address) GetConnection() (proto.BrunoCoinClient, *grpc.ClientConn, error) {
	cc, err := connectToServer(a.Addr)
	if err != nil {
		return nil, nil, err
	}
	return proto.NewBrunoCoinClient(cc), cc, err
}

func (a *Address) VersionRPC(request *proto.VersionRequest) (*proto.Empty, error) {
	c, cc, err := a.GetConnection()
	if err != nil {
		return nil, err
	}
	defer func() {
		err := cc.Close()
		if err != nil {
			fmt.Printf("ERROR {Address.VersionRPC}: " +
				"error when closing connection")
		}
	}()
	reply, err := c.Version(context.Background(), request)
	a.SentVer = time.Now()
	return reply, err
}

func (a *Address) GetAddressesRPC(request *proto.Empty) (*proto.Addresses, error) {
	c, cc, err := a.GetConnection()
	if err != nil {
		return nil, err
	}
	defer func() {
		err := cc.Close()
		if err != nil {
			fmt.Printf("ERROR {Address.GetAddressesRPC}: " +
				"error when closing connection")
		}
	}()
	reply, err := c.GetAddresses(context.Background(), request)
	return reply, err
}

func (a *Address) SendAddressesRPC(request *proto.Addresses) (*proto.Empty, error) {
	c, cc, err := a.GetConnection()
	if err != nil {
		return nil, err
	}
	defer func() {
		err := cc.Close()
		if err != nil {
			fmt.Printf("ERROR {Address.SendAddressesRPC}: " +
				"error when closing connection")
		}
	}()
	reply, err := c.SendAddresses(context.Background(), request)
	return reply, err
}

func (a *Address) RegisterRPC(request *proto.Registration) (*proto.Certificate, error) {
	c, cc, err := a.GetConnection()
	if err != nil {
		return nil, err
	}
	defer func() {
		err := cc.Close()
		if err != nil {
			fmt.Printf("ERROR {Address.ForwardBlockRPC}: " +
				"error when closing connection")
		}
	}()
	reply, err := c.Register(context.Background(), request)
	return reply, err
}

func (a *Address) AddMemberRPC(request *proto.EncKeysMem) (*proto.Empty, error) {
	c, cc, err := a.GetConnection()
	if err != nil {
		return nil, err
	}
	defer func() {
		err := cc.Close()
		if err != nil {
			fmt.Printf("ERROR {Address.ForwardBlockRPC}: " +
				"error when closing connection")
		}
	}()
	reply, err := c.AddMember(context.Background(), request)
	return reply, err
}

func (a *Address) KickMemberRPC(request *proto.EncKeysMem) (*proto.Empty, error) {
	c, cc, err := a.GetConnection()
	if err != nil {
		return nil, err
	}
	defer func() {
		err := cc.Close()
		if err != nil {
			fmt.Printf("ERROR {Address.ForwardBlockRPC}: " +
				"error when closing connection")
		}
	}()
	reply, err := c.KickMember(context.Background(), request)
	return reply, err
}

func (a *Address) GroupMessageRPC(request *proto.GroupIM) (*proto.Empty, error) {
	c, cc, err := a.GetConnection()
	if err != nil {
		return nil, err
	}
	defer func() {
		err := cc.Close()
		if err != nil {
			fmt.Printf("ERROR {Address.ForwardBlockRPC}: " +
				"error when closing connection")
		}
	}()
	reply, err := c.GroupMessage(context.Background(), request)
	return reply, err
}
