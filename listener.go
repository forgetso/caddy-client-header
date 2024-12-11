package caddy_ja3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"io"
	"net"
)

func init() {
	caddy.RegisterModule(JA3Listener{})
}

type JA3Listener struct {
	cache *Cache
	log   *zap.Logger
}

type tlsClientHelloListener struct {
	net.Listener
	cache *Cache
	log   *zap.Logger
}

// CaddyModule implements caddy.Module
func (JA3Listener) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.ja3",
		New: func() caddy.Module { return new(JA3Listener) },
	}
}

func (l *JA3Listener) Provision(ctx caddy.Context) error {
	a, err := ctx.App(CacheAppId)
	if err != nil {
		return err
	}

	l.cache = a.(*Cache)
	l.log = ctx.Logger(l)
	return nil
}

// WrapListener implements caddy.ListenerWrapper
func (l *JA3Listener) WrapListener(ln net.Listener) net.Listener {
	return &tlsClientHelloListener{
		ln,
		l.cache,
		l.log,
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (l *JA3Listener) UnmarshalCaddyfile(_ *caddyfile.Dispenser) error {
	// no-op impl
	return nil
}

// Accept implements net.Listener
func (l *tlsClientHelloListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {

		return conn, err
	}

	l.log.Info("Reading ClientHello for " + conn.RemoteAddr().String())
	ch, err := ReadClientHello(conn)
	if err == nil {
		addr := conn.RemoteAddr().String()
		if err := l.cache.SetClientHello(addr, ch); err != nil {
			l.log.Error("Failed to cache JA3 for "+addr, zap.Error(err))
		}

		l.log.Debug("Cached JA3 for " + conn.RemoteAddr().String())
	} else {
		l.log.Debug("Failed to read ClientHello for "+conn.RemoteAddr().String(), zap.Error(err))
	}

	l.log.Info("ClientHello: " + string(ch))

	return RewindConn(conn, ch)
}

// Close implements net.Listener
func (l *tlsClientHelloListener) Close() error {
	addr := l.Listener.Addr().String()

	l.cache.ClearJA3(addr)
	l.log.Debug("Disposing of JA3 for " + addr)

	return l.Listener.Close()
}

func ReadClientHello(r io.Reader) (ch []byte, err error) {

	buf := make([]byte, 2000)
	for {
		n, err := r.Read(buf)
		fmt.Println(n, err, buf[:n])
		if err == io.EOF {
			fmt.Println("EOF at", zap.Int("n", n))
			break
		}
	}

	// Read a TLS record
	// Read all the bytes from the reader
	raw := make([]byte, 2000)
	if _, err = io.ReadFull(r, raw); err != nil {
		return
	}

	// Check if the first byte is 0x16 (TLS Handshake)
	if raw[0] != 0x16 {
		err = errors.New("not a TLS handshake record")
		return
	}

	// Read exactly 2000 length bytes from the reader
	raw = append(raw, make([]byte, binary.BigEndian.Uint16(raw[3:2000]))...)
	_, err = io.ReadFull(r, raw[2000:])
	return raw, nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*JA3Listener)(nil)
	_ caddy.ListenerWrapper = (*JA3Listener)(nil)
	_ caddyfile.Unmarshaler = (*JA3Listener)(nil)
)
