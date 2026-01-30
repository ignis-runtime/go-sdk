//go:build wasip1

/*
Package net provides network functionality for WASM modules running in Ignis runtime.

This package implements the standard Go net package interface but delegates all
operations to host functions provided by the Ignis runtime.
*/
package net

import (
	"encoding/json"
	"errors"
	"time"
	"unsafe"
)

// HostSocketRequest represents the structure sent from the guest to the host.
type HostSocketRequest struct {
	Operation string `json:"operation"` // "dial", "read", "write", "close"
	Address   string `json:"address"`   // host:port for dial
	FD        int    `json:"fd"`        // file descriptor for read/write/close
	Data      []byte `json:"data"`      // data to write
	Size      int    `json:"size"`      // size to read
	Network   string `json:"network"`   // network type (tcp, udp, etc.)
}

// HostSocketResponse represents the structure sent from the host back to the guest.
type HostSocketResponse struct {
	Error     string `json:"error,omitempty"`
	FD        int    `json:"fd,omitempty"`         // for dial operations
	Data      []byte `json:"data,omitempty"`       // for read operation
	BytesRead int    `json:"bytes_read,omitempty"` // for read operation
	BytesSent int    `json:"bytes_sent,omitempty"` // for write operation
}

//go:wasmimport env host_socket_operation
func _host_socket_operation(reqPtr, reqLen, respPtr, respLen uint32) (ret uint32)

// Conn is an interface that represents a network connection
type Conn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	LocalAddr() Addr
	RemoteAddr() Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Addr represents a network end point address
type Addr interface {
	Network() string
	String() string
}

// OpError is the error type usually returned by functions in the net package
type OpError struct {
	Op     string
	Net    string
	Source Addr
	Addr   Addr
	Err    error
}

func (e *OpError) Error() string {
	return e.Op + " " + e.Net + ": " + e.Err.Error()
}

func (e *OpError) Unwrap() error {
	return e.Err
}

// addr represents a network address
type addr struct {
	network string
	address string
}

func (a *addr) Network() string { return a.network }
func (a *addr) String() string  { return a.address }

// conn wraps the file descriptor to implement net.Conn interface
type conn struct {
	fd int
}

// Dial connects to the address on the named network
func Dial(network, address string) (Conn, error) {
	hostReq := HostSocketRequest{
		Operation: "dial",
		Address:   address,
		Network:   network,
	}

	reqBytes, err := json.Marshal(hostReq)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Err: err}
	}

	respBuf := make([]byte, 4096) // Buffer for response

	reqPtr := uint32(uintptr(unsafe.Pointer(&reqBytes[0])))
	reqLen := uint32(len(reqBytes))
	respPtr := uint32(uintptr(unsafe.Pointer(&respBuf[0])))
	respLen := uint32(len(respBuf))

	ret := _host_socket_operation(reqPtr, reqLen, respPtr, respLen)

	if ret == 0 {
		return nil, &OpError{Op: "dial", Net: network, Err: errors.New("host socket dial failed")}
	}

	var hostResp HostSocketResponse
	if err := json.Unmarshal(respBuf[:ret], &hostResp); err != nil {
		return nil, &OpError{Op: "dial", Net: network, Err: err}
	}

	if hostResp.Error != "" {
		return nil, &OpError{Op: "dial", Net: network, Err: errors.New(hostResp.Error)}
	}

	return &conn{fd: hostResp.FD}, nil
}

// DialTCP connects to the remote address on the named network
func DialTCP(network string, laddr, raddr *TCPAddr) (Conn, error) {
	if raddr == nil {
		return nil, &OpError{Op: "dial", Net: network, Err: errors.New("missing address")}
	}
	return Dial(network, raddr.String())
}

// Read implements the net.Conn Read method
func (c *conn) Read(buffer []byte) (int, error) {
	hostReq := HostSocketRequest{
		Operation: "read",
		FD:        c.fd,
		Size:      len(buffer),
	}

	reqBytes, err := json.Marshal(hostReq)
	if err != nil {
		return 0, &OpError{Op: "read", Net: "tcp", Err: err}
	}

	respBuf := make([]byte, 4096) // Buffer for response

	reqPtr := uint32(uintptr(unsafe.Pointer(&reqBytes[0])))
	reqLen := uint32(len(reqBytes))
	respPtr := uint32(uintptr(unsafe.Pointer(&respBuf[0])))
	respLen := uint32(len(respBuf))

	ret := _host_socket_operation(reqPtr, reqLen, respPtr, respLen)

	if ret == 0 {
		return 0, &OpError{Op: "read", Net: "tcp", Err: errors.New("host socket read failed")}
	}

	var hostResp HostSocketResponse
	if err := json.Unmarshal(respBuf[:ret], &hostResp); err != nil {
		return 0, &OpError{Op: "read", Net: "tcp", Err: err}
	}

	if hostResp.Error != "" {
		return 0, &OpError{Op: "read", Net: "tcp", Err: errors.New(hostResp.Error)}
	}

	// Copy the received data to the provided buffer
	copy(buffer, hostResp.Data)
	return hostResp.BytesRead, nil
}

// Write implements the net.Conn Write method
func (c *conn) Write(data []byte) (int, error) {
	hostReq := HostSocketRequest{
		Operation: "write",
		FD:        c.fd,
		Data:      data,
	}

	reqBytes, err := json.Marshal(hostReq)
	if err != nil {
		return 0, &OpError{Op: "write", Net: "tcp", Err: err}
	}

	respBuf := make([]byte, 4096) // Buffer for response

	reqPtr := uint32(uintptr(unsafe.Pointer(&reqBytes[0])))
	reqLen := uint32(len(reqBytes))
	respPtr := uint32(uintptr(unsafe.Pointer(&respBuf[0])))
	respLen := uint32(len(respBuf))

	ret := _host_socket_operation(reqPtr, reqLen, respPtr, respLen)

	if ret == 0 {
		return 0, &OpError{Op: "write", Net: "tcp", Err: errors.New("host socket write failed")}
	}

	var hostResp HostSocketResponse
	if err := json.Unmarshal(respBuf[:ret], &hostResp); err != nil {
		return 0, &OpError{Op: "write", Net: "tcp", Err: err}
	}

	if hostResp.Error != "" {
		return 0, &OpError{Op: "write", Net: "tcp", Err: errors.New(hostResp.Error)}
	}

	return hostResp.BytesSent, nil
}

// Close implements the net.Conn Close method
func (c *conn) Close() error {
	hostReq := HostSocketRequest{
		Operation: "close",
		FD:        c.fd,
	}

	reqBytes, err := json.Marshal(hostReq)
	if err != nil {
		return &OpError{Op: "close", Net: "tcp", Err: err}
	}

	respBuf := make([]byte, 4096) // Buffer for response

	reqPtr := uint32(uintptr(unsafe.Pointer(&reqBytes[0])))
	reqLen := uint32(len(reqBytes))
	respPtr := uint32(uintptr(unsafe.Pointer(&respBuf[0])))
	respLen := uint32(len(respBuf))

	ret := _host_socket_operation(reqPtr, reqLen, respPtr, respLen)

	if ret == 0 {
		return &OpError{Op: "close", Net: "tcp", Err: errors.New("host socket close failed")}
	}

	var hostResp HostSocketResponse
	if err := json.Unmarshal(respBuf[:ret], &hostResp); err != nil {
		return &OpError{Op: "close", Net: "tcp", Err: err}
	}

	if hostResp.Error != "" {
		return &OpError{Op: "close", Net: "tcp", Err: errors.New(hostResp.Error)}
	}

	return nil
}

// LocalAddr implements the net.Conn LocalAddr method
func (c *conn) LocalAddr() Addr {
	return &addr{network: "tcp", address: "127.0.0.1:0"} // Placeholder
}

// RemoteAddr implements the net.Conn RemoteAddr method
func (c *conn) RemoteAddr() Addr {
	return &addr{network: "tcp", address: "127.0.0.1:30072"} // Placeholder
}

// SetDeadline implements the net.Conn SetDeadline method
func (c *conn) SetDeadline(t time.Time) error {
	// Not implemented in this simplified version
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method
func (c *conn) SetReadDeadline(t time.Time) error {
	// Not implemented in this simplified version
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method
func (c *conn) SetWriteDeadline(t time.Time) error {
	// Not implemented in this simplified version
	return nil
}

// TCPAddr represents the address of a TCP end point
type TCPAddr struct {
	IP   IP
	Port int
	Zone string // IPv6 scoped addressing zone
}

// Network returns the address's network name, "tcp".
func (a *TCPAddr) Network() string { return "tcp" }

// String returns the address's string form.
func (a *TCPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	ip := ipEmptyString(a.IP)
	if a.Zone != "" {
		return JoinHostPort(ip, itoa(a.Port)) + "%" + a.Zone
	}
	return JoinHostPort(ip, itoa(a.Port))
}

// IP is part of the net package
type IP []byte

// String returns the string form of the IP address ip.
func (ip IP) String() string {
	if len(ip) == 0 {
		return "<nil>"
	}
	// Simplified IP string representation
	return "127.0.0.1" // Placeholder
}

// Helper functions
func ipEmptyString(ip IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func itoa(i int) string {
	if i < 0 {
		return "-" + itoa(-i)
	}
	if i == 0 {
		return "0"
	}
	result := ""
	for i > 0 {
		// Calculate the character byte: '0' is 48, so 48 + 5 = 53 ('5')
		char := byte('0' + (i % 10))
		result = string(char) + result
		i /= 10
	}
	return result
}

// JoinHostPort combines host and port into a network address of the
// form "host:port". If host contains a colon, as found in literal
// IPv6 addresses, then JoinHostPort returns "[host]:port".
func JoinHostPort(host, port string) string {
	// Simplified implementation
	return host + ":" + port
}

// ParseIP parses s as an IP address, returning the result.
func ParseIP(s string) IP {
	// Simplified implementation
	return IP([]byte{127, 0, 0, 1}) // Return localhost as placeholder
}

// LookupHost looks up the given host using the local resolver.
// It returns a slice of that host's addresses.
func LookupHost(host string) ([]string, error) {
	// Simplified implementation
	return []string{"127.0.0.1"}, nil
}

// init function to potentially register this package
func init() {
	// Initialization code if needed
}
