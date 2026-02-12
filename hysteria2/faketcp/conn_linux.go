//go:build linux

package faketcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Supported reports whether FakeTCP is supported on the current platform.
func Supported() bool { return true }

var (
	errTimeout = errors.New("faketcp: timeout")
	errClosed  = errors.New("faketcp: connection closed")
)

const (
	flowExpire     = time.Minute
	cleanInterval  = time.Minute
	maxPacketSize  = 2048
	messageQueueCh = 1024
)

// message is a datagram received from the raw socket.
type message struct {
	data []byte
	addr net.Addr
}

// tcpFlow tracks the TCP state for one peer address.
type tcpFlow struct {
	conn         *net.TCPConn // the real TCP connection (for handshake state)
	handle       *net.IPConn  // raw socket handle for sending
	seq          uint32
	ack          uint32
	ts           time.Time
	localIP      net.IP // local IP for checksum
	remoteIP     net.IP // remote IP for checksum
}

// TCPConn is a fake TCP packet-oriented connection implementing net.PacketConn.
type TCPConn struct {
	die     chan struct{}
	dieOnce sync.Once

	// Client mode: the dialed TCP connection
	tcpConn *net.TCPConn
	// Server mode: the TCP listener
	listener *net.TCPListener

	// Raw IP socket handles
	handles []*net.IPConn

	// Received messages channel
	chMessage chan message

	// Flow table keyed by remote address string
	flowTable map[string]*tcpFlow
	flowsLock sync.Mutex

	// Firewall cleanup function
	firewallCleanup func() error

	// Deadlines
	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

// applySocketControl applies the SocketControl function to a net.Conn's underlying fd.
func applySocketControl(conn syscall.Conn, controlFunc func(string, string, syscall.RawConn) error, network, address string) error {
	if controlFunc == nil {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return controlFunc(network, address, raw)
}

// setTTL sets the IP TTL (or IPv6 Hop Limit) on a TCP connection.
func setTTL(c *net.TCPConn, ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.TCPAddr)
	var sErr error
	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			sErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else {
		raw.Control(func(fd uintptr) {
			sErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return sErr
}

// Dial creates a client-side fake TCP connection to the given address.
// It returns a net.PacketConn that wraps QUIC packets in TCP headers.
func Dial(ctx context.Context, network, address string, opts Options) (*TCPConn, error) {
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// 1. Create raw IP socket with fwmark
	handle, err := net.DialIP("ip:tcp", nil, &net.IPAddr{IP: raddr.IP})
	if err != nil {
		return nil, err
	}
	if err := applySocketControl(handle, opts.SocketControl, "ip:tcp", raddr.IP.String()); err != nil {
		handle.Close()
		return nil, err
	}

	// 2. Create real TCP connection (for 3-way handshake) with fwmark via Dialer.Control
	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			if opts.SocketControl != nil {
				return opts.SocketControl(network, address, c)
			}
			return nil
		},
	}
	tcpConnGeneric, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		handle.Close()
		return nil, err
	}
	tcpConn := tcpConnGeneric.(*net.TCPConn)

	// 3. Build the TCPConn
	conn := &TCPConn{
		die:       make(chan struct{}),
		flowTable: make(map[string]*tcpFlow),
		tcpConn:   tcpConn,
		chMessage: make(chan message, messageQueueCh),
		handles:   []*net.IPConn{handle},
	}

	localPort := tcpConn.LocalAddr().(*net.TCPAddr).Port

	// Initialize flow for the remote address
	conn.lockflow(tcpConn.RemoteAddr(), func(e *tcpFlow) {
		e.conn = tcpConn
		e.handle = handle
		e.localIP = tcpConn.LocalAddr().(*net.TCPAddr).IP
		e.remoteIP = raddr.IP
	})

	// 4. Start capture goroutine — it will process the buffered SYN-ACK
	//    and initialize seq/ack asynchronously. WriteTo silently drops
	//    packets until seq/ack are ready; QUIC handles retransmission.
	go conn.captureFlow(handle, localPort)
	go conn.cleaner()

	// 5. Set TTL=1 on the real TCP connection
	if err := setTTL(tcpConn, 1); err != nil {
		conn.Close()
		return nil, err
	}

	// 6. Setup firewall rule to DROP TTL=1 packets
	if opts.FirewallManager != nil {
		cleanup, err := opts.FirewallManager.SetupTTLDrop(TTLDropOptions{
			IsServer:   false,
			LocalPort:  tcpConn.LocalAddr().(*net.TCPAddr).Port,
			RemoteAddr: raddr,
		})
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn.firewallCleanup = cleanup
	}

	// 7. Discard data on the real TCP connection (kernel sends nothing useful due to TTL=1)
	go io.Copy(io.Discard, tcpConn)

	return conn, nil
}

// Listen creates a server-side fake TCP listener on the given address.
// It returns a net.PacketConn that extracts QUIC packets from TCP headers.
func Listen(ctx context.Context, network, address string, opts Options) (*TCPConn, error) {
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	conn := &TCPConn{
		die:       make(chan struct{}),
		flowTable: make(map[string]*tcpFlow),
		chMessage: make(chan message, messageQueueCh),
	}

	// 1. Create raw IP sockets on all interfaces (or specific one)
	if laddr.IP == nil || laddr.IP.IsUnspecified() {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: ipnet.IP})
					if err != nil {
						continue
					}
					if err := applySocketControl(handle, opts.SocketControl, "ip:tcp", ""); err != nil {
						handle.Close()
						continue
					}
					conn.handles = append(conn.handles, handle)
					go conn.captureFlow(handle, laddr.Port)
				}
			}
		}
		if len(conn.handles) == 0 {
			return nil, errors.New("faketcp: no raw sockets could be opened")
		}
	} else {
		handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: laddr.IP})
		if err != nil {
			return nil, err
		}
		if err := applySocketControl(handle, opts.SocketControl, "ip:tcp", ""); err != nil {
			handle.Close()
			return nil, err
		}
		conn.handles = append(conn.handles, handle)
		go conn.captureFlow(handle, laddr.Port)
	}

	// 2. Start TCP listener with SocketControl for fwmark
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if opts.SocketControl != nil {
				return opts.SocketControl(network, address, c)
			}
			return nil
		},
	}
	genericListener, err := lc.Listen(ctx, network, address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.listener = genericListener.(*net.TCPListener)

	// 3. Start cleaner
	go conn.cleaner()

	// 4. Setup firewall rule
	if opts.FirewallManager != nil {
		cleanup, err := opts.FirewallManager.SetupTTLDrop(TTLDropOptions{
			IsServer:  true,
			LocalPort: laddr.Port,
		})
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn.firewallCleanup = cleanup
	}

	// 5. Accept TCP connections (set TTL=1, drain data)
	go func() {
		for {
			tcpConn, err := conn.listener.AcceptTCP()
			if err != nil {
				return
			}
			if err := setTTL(tcpConn, 1); err != nil {
				tcpConn.Close()
				continue
			}
			conn.lockflow(tcpConn.RemoteAddr(), func(e *tcpFlow) {
				e.conn = tcpConn
				e.localIP = tcpConn.LocalAddr().(*net.TCPAddr).IP
				e.remoteIP = tcpConn.RemoteAddr().(*net.TCPAddr).IP
			})
			go io.Copy(io.Discard, tcpConn)
		}
	}()

	return conn, nil
}

// lockflow locks the flow table, looks up or creates an entry, and applies f.
func (conn *TCPConn) lockflow(addr net.Addr, f func(e *tcpFlow)) {
	key := addr.String()
	conn.flowsLock.Lock()
	e := conn.flowTable[key]
	if e == nil {
		e = &tcpFlow{
			ts: time.Now(),
		}
	}
	f(e)
	conn.flowTable[key] = e
	conn.flowsLock.Unlock()
}

// cleaner periodically removes expired flows.
func (conn *TCPConn) cleaner() {
	ticker := time.NewTicker(cleanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-conn.die:
			return
		case <-ticker.C:
			conn.flowsLock.Lock()
			for k, v := range conn.flowTable {
				if time.Since(v.ts) > flowExpire {
					if v.conn != nil {
						setTTL(v.conn, 64)
						v.conn.Close()
					}
					delete(conn.flowTable, k)
				}
			}
			conn.flowsLock.Unlock()
		}
	}
}

// captureFlow reads raw TCP packets from a handle and dispatches payload to chMessage.
func (conn *TCPConn) captureFlow(handle *net.IPConn, port int) {
	buf := make([]byte, maxPacketSize)
	for {
		n, addr, err := handle.ReadFromIP(buf)
		if err != nil {
			return
		}

		if n < 20 { // minimum TCP header size
			continue
		}

		// Auto-detect IP header presence.
		// Linux IPPROTO_TCP raw sockets may or may not include the IP header
		// depending on kernel version. Detect with a heuristic:
		// If it looks like an IPv4/IPv6 header with TCP protocol and matching
		// total length, skip it. Otherwise treat as raw TCP data.
		tcpStart := 0
		if buf[0]>>4 == 4 && n >= 40 {
			// Possible IPv4 header: verify protocol==TCP and totalLen==n
			ihl := int(buf[0]&0x0f) * 4
			totalLen := int(binary.BigEndian.Uint16(buf[2:4]))
			if buf[9] == 6 && ihl >= 20 && ihl < n && totalLen == n {
				tcpStart = ihl
			}
		} else if buf[0]>>4 == 6 && n >= 60 {
			// Possible IPv6 header: verify nextHeader==TCP and payloadLen matches
			if buf[6] == 6 {
				payloadLen := int(binary.BigEndian.Uint16(buf[4:6]))
				if payloadLen == n-40 {
					tcpStart = 40
				}
			}
		}
		tcpData := buf[tcpStart:n]

		// Parse TCP header
		hdr, payload, err := DecodeTCPHeader(tcpData)
		if err != nil {
			continue
		}

		// Port filtering: only accept packets destined to our port
		if int(hdr.DstPort) != port {
			continue
		}

		// Build source address
		src := &net.TCPAddr{
			IP:   addr.IP,
			Port: int(hdr.SrcPort),
		}

		var orphan bool
		// Update flow state
		conn.lockflow(src, func(e *tcpFlow) {
			if e.conn == nil {
				orphan = true
			}
			e.ts = time.Now()
			e.handle = handle

			if hdr.Flags&FlagACK != 0 && e.seq == 0 {
				// Only initialize seq from ACK during handshake.
				// After initialization, WriteTo manages seq exclusively.
				// Without this guard, every incoming ACK resets seq to
				// the peer's (possibly stale) ack value, causing seq
				// regression and overlapping packets.
				e.seq = hdr.Ack
			}
			if hdr.Flags&FlagSYN != 0 {
				e.ack = hdr.Seq + 1
			}
			if hdr.Flags&FlagPSH != 0 {
				if e.ack == hdr.Seq {
					e.ack = hdr.Seq + uint32(len(payload))
				}
			}

			// Store IPs for checksum calculation if not set
			if e.localIP == nil {
				e.localIP = handle.LocalAddr().(*net.IPAddr).IP
			}
			if e.remoteIP == nil {
				e.remoteIP = addr.IP
			}
		})

		// Deliver payload from PSH packets that belong to known flows
		if !orphan && hdr.Flags&FlagPSH != 0 && len(payload) > 0 {
			p := make([]byte, len(payload))
			copy(p, payload)
			select {
			case conn.chMessage <- message{data: p, addr: src}:
			case <-conn.die:
				return
			}
		}
	}
}

// ReadFrom implements net.PacketConn.
func (conn *TCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := conn.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, nil, errTimeout
	case <-conn.die:
		return 0, nil, errClosed
	case msg := <-conn.chMessage:
		n = copy(p, msg.data)
		return n, msg.addr, nil
	}
}

// WriteTo implements net.PacketConn.
func (conn *TCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var deadline <-chan time.Time
	if d, ok := conn.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, errTimeout
	case <-conn.die:
		return 0, errClosed
	default:
		raddr, resolveErr := net.ResolveTCPAddr("tcp", addr.String())
		if resolveErr != nil {
			return 0, resolveErr
		}

		var lport int
		if conn.tcpConn != nil {
			lport = conn.tcpConn.LocalAddr().(*net.TCPAddr).Port
		} else if conn.listener != nil {
			lport = conn.listener.Addr().(*net.TCPAddr).Port
		}

		// In client mode, QUIC may pass an address with nil IP (e.g. ":22031")
		// which won't match the flow created with tcpConn.RemoteAddr() ("1.2.3.4:22031").
		// Use the TCP connection's remote address for flow lookup in client mode.
		flowAddr := addr
		if conn.tcpConn != nil {
			flowAddr = conn.tcpConn.RemoteAddr()
		}

		conn.lockflow(flowAddr, func(e *tcpFlow) {
			if e.handle == nil {
				// No handle yet; drop silently (flow not established)
				n = len(p)
				return
			}

			// Drop silently if seq/ack not yet initialized from SYN-ACK.
			// captureFlow will set these asynchronously; QUIC retransmits.
			if e.seq == 0 && e.ack == 0 {
				n = len(p)
				return
			}

			// Determine local and remote IPs for checksum
			localIP := e.localIP
			remoteIP := e.remoteIP
			if localIP == nil {
				localIP = e.handle.LocalAddr().(*net.IPAddr).IP
			}
			if remoteIP == nil {
				remoteIP = raddr.IP
			}

			// Random window size (>= 32768)
			var windowBytes [2]byte
			rand.Read(windowBytes[:])
			window := binary.BigEndian.Uint16(windowBytes[:]) | 0x8000

			// Build TCP header
			hdr := &TCPHeader{
				SrcPort: uint16(lport),
				DstPort: uint16(raddr.Port),
				Seq:     e.seq,
				Ack:     e.ack,
				Flags:   FlagPSH | FlagACK,
				Window:  window,
			}

			// Encode and send
			packet := EncodeTCPPacket(hdr, p, localIP, remoteIP)
			if conn.tcpConn != nil {
				_, err = e.handle.Write(packet)
			} else {
				_, err = e.handle.WriteToIP(packet, &net.IPAddr{IP: raddr.IP})
			}

			// Advance sequence number
			e.seq += uint32(len(p))
			n = len(p)
		})
	}
	return
}

// Close closes the fake TCP connection and cleans up resources.
func (conn *TCPConn) Close() error {
	var closeErr error
	conn.dieOnce.Do(func() {
		close(conn.die)

		// Close TCP connections
		if conn.tcpConn != nil {
			setTTL(conn.tcpConn, 64)
			closeErr = conn.tcpConn.Close()
		} else if conn.listener != nil {
			closeErr = conn.listener.Close()
			conn.flowsLock.Lock()
			for k, v := range conn.flowTable {
				if v.conn != nil {
					setTTL(v.conn, 64)
					v.conn.Close()
				}
				delete(conn.flowTable, k)
			}
			conn.flowsLock.Unlock()
		}

		// Close raw handles
		for _, h := range conn.handles {
			h.Close()
		}

		// Cleanup firewall rules
		if conn.firewallCleanup != nil {
			conn.firewallCleanup()
		}
	})
	return closeErr
}

// LocalAddr returns the local network address.
func (conn *TCPConn) LocalAddr() net.Addr {
	if conn.tcpConn != nil {
		return conn.tcpConn.LocalAddr()
	} else if conn.listener != nil {
		return conn.listener.Addr()
	}
	return nil
}

// SetDeadline implements net.PacketConn.
func (conn *TCPConn) SetDeadline(t time.Time) error {
	conn.SetReadDeadline(t)
	conn.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline implements net.PacketConn.
func (conn *TCPConn) SetReadDeadline(t time.Time) error {
	conn.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline implements net.PacketConn.
func (conn *TCPConn) SetWriteDeadline(t time.Time) error {
	conn.writeDeadline.Store(t)
	return nil
}

// SetReadBuffer sets the read buffer size on the raw sockets.
func (conn *TCPConn) SetReadBuffer(bytes int) error {
	for _, h := range conn.handles {
		if err := h.SetReadBuffer(bytes); err != nil {
			return err
		}
	}
	return nil
}

// SetWriteBuffer sets the write buffer size on the raw sockets.
func (conn *TCPConn) SetWriteBuffer(bytes int) error {
	for _, h := range conn.handles {
		if err := h.SetWriteBuffer(bytes); err != nil {
			return err
		}
	}
	return nil
}
