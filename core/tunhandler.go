package core

import (
	"context"
	"errors"
	"github.com/wencaiwulue/kubevpn/config"
	"net"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	log "github.com/sirupsen/logrus"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func ipToTunRouteKey(ip net.IP) string {
	return ip.To16().String()
}

type tunHandler struct {
	chain  *Chain
	node   *Node
	routes *sync.Map
	chExit chan struct{}
}

// TunHandler creates a handler for tun tunnel.
func TunHandler(chain *Chain, node *Node) Handler {
	return &tunHandler{
		chain:  chain,
		node:   node,
		routes: &sync.Map{},
		chExit: make(chan struct{}, 1),
	}
}

func (h *tunHandler) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	var err error
	var raddr net.Addr
	if addr := h.node.Remote; addr != "" {
		raddr, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Debugf("[tun] %s: remote addr: %v", conn.LocalAddr(), err)
			return
		}
	}

	var tempDelay time.Duration
	for ctx.Err() == nil {
		err = func() error {
			if raddr != nil && !h.chain.IsEmpty() {
				return h.transportTunToRemote(ctx, conn)
			} else {
				return h.transportTun(ctx, conn, raddr)
			}
		}()
		if err != nil {
			log.Debugf("[tun] %s: %v", conn.LocalAddr(), err)
		}

		select {
		case <-h.chExit:
			return
		case <-ctx.Done():
			h.chExit <- struct{}{}
		default:
			log.Warnf("next loop, err: %v", err)
		}

		if err != nil {
			if tempDelay == 0 {
				tempDelay = 1000 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 6 * time.Second; tempDelay > max {
				tempDelay = max
			}
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
	}
}

func (h *tunHandler) getNewConn(ctx context.Context) (net.PacketConn, error) {
	cc, err := h.chain.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	var ok bool
	pc, ok := cc.(net.PacketConn)
	if !ok {
		err = errors.New("not a packet connection")
		return nil, err
	}
	return pc, nil
}

func (h *tunHandler) findRouteFor(dst net.IP) net.Addr {
	if v, ok := h.routes.Load(ipToTunRouteKey(dst)); ok {
		return v.(net.Addr)
	}
	//for _, route := range h.options.IPRoutes {
	//	if route.Dest.Contains(dst) && route.Gateway != nil {
	//		if v, ok := h.routes.Load(ipToTunRouteKey(route.Gateway)); ok {
	//			return v.(net.Addr)
	//		}
	//	}
	//}
	return nil
}

func (h *tunHandler) transportTunToRemote(ctx context.Context, tun net.Conn) error {
	errChan := make(chan error, 2)
	var toRemote = make(chan []byte, 1000*1000)
	var toTun = make(chan []byte, 1000*1000)

	go func() {
		for ctx.Err() == nil {
			err := func() error {
				b := SPool.Get().([]byte)
				n, err := tun.Read(b)
				if err != nil {
					select {
					case h.chExit <- struct{}{}:
					default:
					}
					return err
				}
				toRemote <- b[:n]
				return nil
			}()

			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		for bytes := range toTun {
			func() {
				defer SPool.Put(bytes)
				if _, err := tun.Write(bytes); err != nil {
					log.Errorln(err)
					return
				}
			}()
		}
	}()

	for i := 0; i < 10; i++ {
		tcpConn, err := h.getNewConn(ctx)
		if err != nil {
			return err
		}
		go func(tcpConn net.PacketConn) {
			defer tcpConn.Close()
			go func() {
				for bytes := range toRemote {
					func() {
						defer SPool.Put(bytes)
						_, err = tcpConn.WriteTo(bytes, nil)
						if err != nil {
							errChan <- err
							return
						}
					}()
				}
			}()

			for ctx.Err() == nil {
				err = func() error {
					b := SPool.Get().([]byte)
					defer SPool.Put(b)
					n, _, err := tcpConn.ReadFrom(b)
					if err != nil && err != shadowaead.ErrShortPacket {
						return err
					}
					toTun <- b[:n]
					return nil
				}()
				if err != nil {
					errChan <- err
					return
				}
			}
		}(tcpConn)
	}

	select {
	case err := <-errChan:
		log.Errorln(err)
		return err
	case <-ctx.Done():
		return nil
	}
}

func (h *tunHandler) transportTun(ctx context.Context, tun net.Conn, raddr net.Addr) error {
	laddr, _ := net.ResolveUDPAddr("udp", h.node.Addr)
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		errChan := make(chan error, 2)
		go func() {
			for ctx.Err() == nil {
				err := func() error {
					b := SPool.Get().([]byte)
					defer SPool.Put(b)
					n, err := tun.Read(b)
					if err != nil {
						select {
						case h.chExit <- struct{}{}:
						default:
						}
						return err
					}

					// client side, deliver packet directly.
					if raddr != nil {
						_, err = conn.WriteTo(b[:n], raddr)
						return err
					}

					var src, dst net.IP
					if waterutil.IsIPv4(b[:n]) {
						header, err := ipv4.ParseHeader(b[:n])
						if err != nil {
							log.Debugf("[tun] %s: %v", tun.LocalAddr(), err)
							return nil
						}
						if config.Debug {
							log.Debugf("[tun] %s", header.String())
						}
						src, dst = header.Src, header.Dst
					} else if waterutil.IsIPv6(b[:n]) {
						header, err := ipv6.ParseHeader(b[:n])
						if err != nil {
							log.Debugf("[tun] %s: %v", tun.LocalAddr(), err)
							return nil
						}
						if config.Debug {
							log.Debugf("[tun] %s", header.String())
						}
						src, dst = header.Src, header.Dst
					} else {
						log.Debugf("[tun] unknown packet")
						return nil
					}

					addr := h.findRouteFor(dst)
					if addr == nil {
						log.Debugf("[tun] no route for %s -> %s", src, dst)
						return nil
					}

					if config.Debug {
						log.Debugf("[tun] find route: %s -> %s", dst, addr)
					}
					_, err = conn.WriteTo(b[:n], addr)
					return err
				}()

				if err != nil {
					errChan <- err
					return
				}
			}
		}()

		go func() {
			for ctx.Err() == nil {
				err := func() error {
					b := SPool.Get().([]byte)
					defer SPool.Put(b)

					n, addr, err := conn.ReadFrom(b)
					if err != nil && err != shadowaead.ErrShortPacket {
						return err
					}

					// client side, deliver packet to tun device.
					if raddr != nil {
						_, err = tun.Write(b[:n])
						return err
					}

					var src, dst net.IP
					if waterutil.IsIPv4(b[:n]) {
						header, err := ipv4.ParseHeader(b[:n])
						if err != nil {
							log.Debugf("[tun] %s: %v", tun.LocalAddr(), err)
							return nil
						}
						if config.Debug {
							log.Debugf("[tun] %s", header.String())
						}
						src, dst = header.Src, header.Dst
					} else if waterutil.IsIPv6(b[:n]) {
						header, err := ipv6.ParseHeader(b[:n])
						if err != nil {
							log.Debugf("[tun] %s: %v", tun.LocalAddr(), err)
							return nil
						}
						if config.Debug {
							log.Debugf("[tun] %s", header.String())
						}
						src, dst = header.Src, header.Dst
					} else {
						log.Debugf("[tun] unknown packet")
						return nil
					}

					routeKey := ipToTunRouteKey(src)
					if actual, loaded := h.routes.LoadOrStore(routeKey, addr); loaded {
						if actual.(net.Addr).String() != addr.String() {
							log.Debugf("[tun] update route: %s -> %s (old %s)", src, addr, actual.(net.Addr))
							h.routes.Store(routeKey, addr)
						}
					} else {
						log.Debugf("[tun] new route: %s -> %s", src, addr)
					}

					if routeToAddr := h.findRouteFor(dst); routeToAddr != nil {
						if config.Debug {
							log.Debugf("[tun] find route: %s -> %s", dst, routeToAddr)
						}
						_, err = conn.WriteTo(b[:n], routeToAddr)
						return err
					}

					if _, err = tun.Write(b[:n]); err != nil {
						select {
						case h.chExit <- struct{}{}:
						default:
						}
						return err
					}
					return nil
				}()

				if err != nil {
					errChan <- err
					return
				}
			}
		}()
		select {
		case err = <-errChan:
			log.Errorln(err)
			continue
		case <-ctx.Done():
			return nil
		}
	}
	return err
}
