package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/kirillfreidman/rotor/internal/pool"
)

// SOCKS5 constants from RFC 1928 (SOCKS5) and RFC 1929 (username/password).
const (
	socks5Version  = 0x05
	authVersion    = 0x01 // version of the RFC 1929 sub-negotiation
	methodUserPass = 0x02
	methodNone     = 0xFF // "no acceptable methods"

	cmdConnect = 0x01 // BIND (0x02) and UDP ASSOCIATE (0x03) are not supported

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded        = 0x00
	repGeneralFailure   = 0x01
	repNotAllowed       = 0x02
	repNetUnreachable   = 0x03
	repHostUnreachable  = 0x04
	repConnRefused      = 0x05
	repTTLExpired       = 0x06
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08
)

var errBadAtyp = errors.New("unsupported address type")

// serveSOCKS5 runs the SOCKS5 handshake, then relays. On the wire:
//
//  1. client greeting   VER=05 NMETHODS METHODS...
//     server choice     VER=05 METHOD            (we only accept 02, user/pass)
//
//  2. auth (RFC 1929)   VER=01 ULEN UNAME PLEN PASSWD
//     server result     VER=01 STATUS            (00 = ok)
//
//  3. request           VER=05 CMD RSV=00 ATYP DST.ADDR DST.PORT
//     server reply      VER=05 REP RSV=00 ATYP BND.ADDR BND.PORT
//
//  4. raw bytes in both directions
//
// Ports and lengths are big-endian ("network byte order").
func (s *Server) serveSOCKS5(c net.Conn, br *bufio.Reader) {
	// 1. Greeting.
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[1] == 0 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// Anonymous access (method 00) is deliberately not offered: an
	// unauthenticated proxy on the internet becomes an open relay for abuse
	// within hours, and it would burn the reputation of every exit IP.
	if !bytes.Contains(methods, []byte{methodUserPass}) {
		c.Write([]byte{socks5Version, methodNone})
		return
	}
	if _, err := c.Write([]byte{socks5Version, methodUserPass}); err != nil {
		return
	}

	// 2. Username/password.
	user, pass, err := readUserPass(br)
	if err != nil {
		return
	}
	t, opts, err := s.Tenants.Authenticate(user, pass)
	if err != nil {
		c.Write([]byte{authVersion, 0x01})
		return
	}
	if _, err := c.Write([]byte{authVersion, 0x00}); err != nil {
		return
	}

	// 3. Request.
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != socks5Version {
		return
	}
	target, err := readAddr(br, req[3])
	if errors.Is(err, errBadAtyp) {
		reply(c, repAtypNotSupported, nil)
		return
	} else if err != nil {
		return
	}
	if req[1] != cmdConnect {
		reply(c, repCmdNotSupported, nil)
		return
	}
	if !t.Acquire() {
		reply(c, repNotAllowed, nil)
		return
	}
	defer t.Release()

	// For a domain (ATYP 03) the proxy resolves the name, from the exit's
	// network. That is what clients mean by "socks5h": DNS does not leak
	// from the client's own network, and geo-aware DNS answers match the
	// exit's location rather than the client's.
	up, e, err := s.dialTarget(t, opts, target)
	if err != nil {
		reply(c, replyForErr(err), nil)
		return
	}
	defer up.Close()
	if err := reply(c, repSucceeded, up.LocalAddr()); err != nil {
		return
	}

	// 4. Relay.
	start := time.Now()
	upN, downN := relay(c, br, up, t, s.Timeouts.Idle.Duration)
	s.logTunnel("socks5", t, opts, e, target, upN, downN, start)
}

func readUserPass(br *bufio.Reader) (user, pass string, err error) {
	ver, err := br.ReadByte()
	if err != nil {
		return "", "", err
	}
	if ver != authVersion {
		return "", "", errors.New("bad auth version")
	}
	if user, err = readLenPrefixed(br); err != nil {
		return "", "", err
	}
	if pass, err = readLenPrefixed(br); err != nil {
		return "", "", err
	}
	return user, pass, nil
}

// readLenPrefixed reads one length byte, then that many bytes.
func readLenPrefixed(br *bufio.Reader) (string, error) {
	n, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(br, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// readAddr reads DST.ADDR and DST.PORT and returns "host:port".
func readAddr(br *bufio.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case atypDomain:
		name, err := readLenPrefixed(br)
		if err != nil {
			return "", err
		}
		if name == "" {
			return "", errors.New("empty domain")
		}
		host = name
	default:
		return "", errBadAtyp
	}
	var p [2]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return "", err
	}
	// JoinHostPort adds [brackets] around IPv6 literals.
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

// reply writes the server's answer to the request. BND.ADDR/BND.PORT is the
// local address of our upstream socket: the exit IP and the ephemeral port.
func reply(c net.Conn, rep byte, bound net.Addr) error {
	b := []byte{socks5Version, rep, 0x00}
	if ta, ok := bound.(*net.TCPAddr); ok {
		if ip4 := ta.IP.To4(); ip4 != nil {
			b = append(b, atypIPv4)
			b = append(b, ip4...)
		} else {
			b = append(b, atypIPv6)
			b = append(b, ta.IP.To16()...)
		}
		b = binary.BigEndian.AppendUint16(b, uint16(ta.Port))
	} else {
		b = append(b, atypIPv4, 0, 0, 0, 0, 0, 0) // 0.0.0.0:0
	}
	_, err := c.Write(b)
	return err
}

// replyForErr maps a dial error to a SOCKS5 reply code.
func replyForErr(err error) byte {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, pool.ErrForbiddenTarget):
		return repNotAllowed
	case errors.Is(err, pool.ErrNoExit):
		return repGeneralFailure
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH), errors.As(err, &dnsErr):
		return repHostUnreachable
	case isTimeout(err):
		// RFC 1928 has no "timed out" code; TTL expired is the usual stand-in.
		return repTTLExpired
	default:
		return repGeneralFailure
	}
}
