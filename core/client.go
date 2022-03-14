package core

import (
	"context"
	"net"
)

type Client struct {
	Connector
	Transporter
}

type Connector interface {
	ConnectContext(ctx context.Context, conn net.Conn) (net.Conn, error)
}

type Transporter interface {
	Dial(addr string) (net.Conn, error)
}
