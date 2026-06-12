package wormhole

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

// DialFunc opens a connection to addr through some network context (a VPN
// tunnel, a tailnet, ...). network is always "tcp" for the SOCKS5 CONNECT
// path. Providers supply one of these; the rest of the network-context
// plumbing is identical regardless of what the tunnel is.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// SOCKS5 reply codes (RFC 1928).
const (
	socksVersion       = 0x05
	socksCmdConnect    = 0x01
	socksRepSuccess    = 0x00
	socksRepFailure    = 0x01
	socksRepCmdNotSup  = 0x07
	socksRepAddrNotSup = 0x08
	socksAtypIPv4      = 0x01
	socksAtypDomain    = 0x03
	socksAtypIPv6      = 0x04
)

// socksServer is a minimal SOCKS5 server supporting no-auth CONNECT only —
// enough for the network-context contract. It dials every CONNECT through
// the provided DialFunc.
type socksServer struct {
	ln     net.Listener
	dial   DialFunc
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newSocksServer(ln net.Listener, dial DialFunc) *socksServer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &socksServer{ln: ln, dial: dial, ctx: ctx, cancel: cancel}
	s.wg.Add(1)
	go s.serve()
	return s
}

func (s *socksServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handle(conn)
		}()
	}
}

func (s *socksServer) stop() error {
	s.cancel()
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *socksServer) handle(c net.Conn) {
	// Greeting: VER, NMETHODS, METHODS...
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil || header[0] != socksVersion {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(header[1])); err != nil {
		return
	}
	// Reply: no authentication required.
	if _, err := c.Write([]byte{socksVersion, 0x00}); err != nil {
		return
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != socksVersion {
		return
	}
	if req[1] != socksCmdConnect {
		s.reply(c, socksRepCmdNotSup)
		return
	}

	host, err := readAddr(c, req[3])
	if err != nil {
		s.reply(c, socksRepAddrNotSup)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf))))

	remote, err := s.dial(s.ctx, "tcp", addr)
	if err != nil {
		s.reply(c, socksRepFailure)
		return
	}
	defer remote.Close()
	if err := s.reply(c, socksRepSuccess); err != nil {
		return
	}

	// Splice both directions. When either copy finishes, close both ends so
	// the other copy unblocks — otherwise a half-open peer (e.g. a server
	// still reading) would wedge the relay forever.
	done := make(chan struct{})
	go func() {
		io.Copy(remote, c)
		remote.Close()
		c.Close()
		close(done)
	}()
	io.Copy(c, remote)
	remote.Close()
	c.Close()
	<-done
}

func readAddr(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case socksAtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return "", err
		}
		name := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return "", err
		}
		return string(name), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

// reply sends a SOCKS5 response with a zero bind address.
func (s *socksServer) reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVersion, code, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
