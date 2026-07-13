// Package ziti provides embedded per-service OpenZiti connectivity for the
// client: dial a named Ziti service in-process, and (for RDP/SSH/VNC/browser
// clients that speak plain TCP) bridge a service to a local 127.0.0.1 loopback
// port. No TUN driver / no elevation — matches the "embedded per-service dial"
// decision. Uses the same openziti/sdk-golang identity the agent enrolled.
package ziti

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/openziti/sdk-golang/ziti"
)

// Dialer holds a loaded Ziti context (an enrolled identity).
type Dialer struct {
	ctx ziti.Context
}

// NewDialer loads the enrolled Ziti identity file and initialises a context.
func NewDialer(identityFile string) (*Dialer, error) {
	cfg, err := ziti.NewConfigFromFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("load ziti identity: %w", err)
	}
	ctx, err := ziti.NewContext(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ziti context: %w", err)
	}
	return &Dialer{ctx: ctx}, nil
}

// Dial opens a connection to the named Ziti service over the overlay.
func (d *Dialer) Dial(service string) (net.Conn, error) {
	return d.ctx.Dial(service)
}

// Close tears down the Ziti context.
func (d *Dialer) Close() {
	if d.ctx != nil {
		d.ctx.Close()
	}
}

// Bridge starts a local TCP listener on 127.0.0.1:0 that forwards every
// accepted connection to the named Ziti service over the overlay. It returns
// the local address (e.g. "127.0.0.1:54321") a plain-TCP client (RDP/SSH/VNC,
// or a browser) connects to, and a stop function. Runs until stop is called.
func (d *Dialer) Bridge(service string) (localAddr string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("loopback listen: %w", err)
	}

	var wg sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				zc, derr := d.ctx.Dial(service)
				if derr != nil {
					return
				}
				defer zc.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(zc, c); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, zc); done <- struct{}{} }()
				<-done
			}()
		}
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		wg.Wait()
	}, nil
}
