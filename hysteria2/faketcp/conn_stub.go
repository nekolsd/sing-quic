//go:build !linux

package faketcp

import (
	"context"
	"errors"
	"net"
	"time"
)

var errNotSupported = errors.New("faketcp is only supported on Linux")

// Supported reports whether FakeTCP is supported on the current platform.
func Supported() bool { return false }

// Dial is not supported on this platform.
func Dial(ctx context.Context, network, address string, opts Options) (*TCPConn, error) {
	return nil, errNotSupported
}

// Listen is not supported on this platform.
func Listen(ctx context.Context, network, address string, opts Options) (*TCPConn, error) {
	return nil, errNotSupported
}

// TCPConn is a stub for non-Linux platforms.
// All methods return errNotSupported. This exists only to satisfy
// the net.PacketConn interface at compile time.
type TCPConn struct{}

func (c *TCPConn) ReadFrom(p []byte) (int, net.Addr, error)  { return 0, nil, errNotSupported }
func (c *TCPConn) WriteTo(p []byte, addr net.Addr) (int, error) { return 0, errNotSupported }
func (c *TCPConn) Close() error                               { return errNotSupported }
func (c *TCPConn) LocalAddr() net.Addr                        { return nil }
func (c *TCPConn) SetDeadline(t time.Time) error              { return errNotSupported }
func (c *TCPConn) SetReadDeadline(t time.Time) error          { return errNotSupported }
func (c *TCPConn) SetWriteDeadline(t time.Time) error         { return errNotSupported }
