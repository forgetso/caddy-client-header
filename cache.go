package caddy_ja3

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"
	"go.uber.org/zap"
	"sync"
)

const (
	CacheAppId = "ja3.cache"
)

func init() {
	caddy.RegisterModule(Cache{})
}

type Cache struct {
	ja3     map[string]string
	ja3Lock sync.RWMutex
}

func (c *Cache) Provision(ctx caddy.Context) error {
	c.ja3 = make(map[string]string)
	return nil
}

func (c *Cache) SetClientHello(l *tlsClientHelloListener, addr string, ch []byte) error {
	c.ja3Lock.Lock()
	defer c.ja3Lock.Unlock()

	parsedCh := &tlsx.ClientHelloBasic{}
	if err := parsedCh.Unmarshal(ch); err != nil {
		return err
	}

	c.ja3[addr] = ja3.DigestHex(parsedCh)

	// Log parsedCh asynchronously using a goroutine
	go func() {
		// Ensure that the logging is done without blocking the main flow
		logParsedClientHello(l, parsedCh)
	}()

	return nil
}

// Log the parsed ClientHello details asynchronously
func logParsedClientHello(l *tlsClientHelloListener, parsedCh *tlsx.ClientHelloBasic) {
	l.log.Info("Parsing ClientHello")
	// Call the String() method to get the formatted representation of the ClientHello
	clientHelloString := parsedCh.String()

	// Log the formatted string
	l.log.Info("Parsed ClientHello", zap.String("ClientHello", clientHelloString))
}

func (c *Cache) ClearJA3(addr string) {
	c.ja3Lock.Lock()
	defer c.ja3Lock.Unlock()
	delete(c.ja3, addr)
}

func (c *Cache) GetJA3(addr string) *string {
	c.ja3Lock.RLock()
	defer c.ja3Lock.RUnlock()

	if md5, found := c.ja3[addr]; found {
		return &md5
	} else {
		return nil
	}
}

// CaddyModule implements caddy.Module
func (Cache) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: CacheAppId,
		New: func() caddy.Module {
			return &Cache{
				ja3:     make(map[string]string),
				ja3Lock: sync.RWMutex{},
			}
		},
	}
}

// Start implements caddy.App
func (c *Cache) Start() error {
	return nil
}

// Stop implements caddy.App
func (c *Cache) Stop() error {
	return nil
}

// Interface guards
var (
	_ caddy.App         = (*Cache)(nil)
	_ caddy.Provisioner = (*Cache)(nil)
)
