// Package faketcp implements a fake TCP transport for QUIC.
//
// It wraps QUIC (UDP) packets in TCP headers using raw sockets,
// making the traffic appear as TCP to firewalls and middleboxes.
// This is useful for bypassing UDP throttling or blocking.
//
// The implementation uses raw IP sockets (SOCK_RAW, IPPROTO_TCP) to send
// and receive packets with crafted TCP headers, while maintaining a real
// TCP connection (with TTL=1) purely for the three-way handshake, so that
// stateful firewalls see a legitimate TCP session.
//
// Only supported on Linux. Requires CAP_NET_RAW and CAP_NET_ADMIN.
package faketcp

import (
	"net"
	"syscall"
)

// FirewallManager manages TTL=1 DROP rules to prevent the kernel's TCP
// stack from interfering with fake TCP connections.
// The implementation is provided by the caller (e.g., sing-box) using
// nftables or iptables as appropriate for the platform.
type FirewallManager interface {
	// SetupTTLDrop adds firewall rules to drop outgoing TCP packets with TTL=1.
	// For clients: drops packets matching the remote address.
	// For servers: drops packets matching the local port.
	// Returns a cleanup function that removes the rules.
	SetupTTLDrop(opts TTLDropOptions) (cleanup func() error, err error)
}

// TTLDropOptions configures the TTL=1 DROP firewall rule.
type TTLDropOptions struct {
	// IsServer indicates whether this is a server (Listen) or client (Dial).
	IsServer bool
	// LocalPort is the local TCP port used by the fake TCP connection.
	LocalPort int
	// RemoteAddr is the remote TCP address (client only; nil for server).
	RemoteAddr *net.TCPAddr
}

// Options configures a fake TCP connection.
type Options struct {
	// SocketControl is called after creating each socket (TCP connections,
	// raw IP sockets) to apply platform-specific settings like SO_MARK (fwmark).
	// This is typically obtained from sing-box's NetworkManager.AutoRedirectOutputMarkFunc().
	// May be nil if no special socket options are needed.
	SocketControl func(network, address string, c syscall.RawConn) error

	// FirewallManager sets up TTL=1 DROP rules.
	// May be nil if no firewall management is needed (rules managed externally).
	FirewallManager FirewallManager
}
