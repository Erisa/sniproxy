package sniproxy

import (
	"encoding/json"
	"net"
)

// ForwardPolicy is a proxy-pattern pair.
type ForwardPolicy struct {
	// ForwardProxies is the addresses of the SOCKS5 proxy that the connections will
	// be forwarded to according to ForwardRules.
	ForwardProxies []string `json:"dst"`

	// ForwardRules is a list of wildcards that define what connections will be
	// forwarded to the proxy using ForwardProxy.  If the list is empty and
	// ForwardProxy is set, all connections will be forwarded.
	ForwardRules []string `json:"src"`
}

type TCPAddr struct {
	*net.TCPAddr
}

func (c *TCPAddr) UnmarshalJSON(data []byte) error {
	var addr string
	if err := json.Unmarshal(data, &addr); err != nil {
		return err
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	c.TCPAddr = tcpAddr
	return nil
}

// Config is the SNI proxy configuration.
type Config struct {
	// TLSListenAddr is the listen address the SNI proxy will be listening to
	// TLS connections.
	TLSListenAddr *TCPAddr `json:"tls_listen_addr"`

	// HTTPListenAddr is the listen address the SNI proxy will be listening to
	// plain HTTP connections.
	HTTPListenAddr *TCPAddr `json:"http_listen_addr"`

	// Forwards is a list of forwarding policies.
	Forwards []ForwardPolicy `json:"forwards"`

	// BlockRules is a list of wildcards that define connections to which hosts
	// will be blocked.
	BlockRules []string `json:"block_rules"`

	// DropRules is a list of wildcards that define connections to which hosts
	// will be dropped. "Dropped" means that they will be delayed for a specific
	// period of time.
	DropRules []string `json:"drop_rules"`

	// BandwidthRate is a number of bytes per second the connections speed will
	// be limited to.  If not set, there is no limit.
	BandwidthRate float64 `json:"bandwidth_rate"`

	// BandwidthRules is a map that allows to define connection speed for
	// domains that match the wildcards.  Has higher priority than
	// BandwidthRate.
	BandwidthRules map[string]float64 `json:"bandwidth_rules"`
}
