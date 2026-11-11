//go:build linux

package lab

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// HelperEnv names the environment variable that turns the test binary into a lab helper.
const HelperEnv = "SEAWARD_LAB_HELPER"

// RunHelper runs one helper role and returns the exit code. The test binary calls it from
// TestMain when HelperEnv is set, so the lab needs no tool of its own inside the namespaces.
func RunHelper(role string, args []string, stdout io.Writer) int {
	switch role {
	case "listen":
		if len(args) != 1 {
			fmt.Fprintln(stdout, "FAIL usage: listen <file>")
			return 2
		}
		return helperListen(args[0], stdout)
	case "probe":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: probe <file> <timeout ms>")
			return 2
		}
		ms, err := strconv.Atoi(args[1])
		if err != nil || ms <= 0 {
			fmt.Fprintln(os.Stderr, "probe: bad timeout")
			return 2
		}
		return helperProbe(args[0], time.Duration(ms)*time.Millisecond, stdout)
	}
	fmt.Fprintf(os.Stderr, "unknown helper role %q\n", role)
	return 2
}

// listenLife bounds how long a listener lives if nobody stops it. The script kills it when it is
// done, and the parent-death signal covers a killed script; this is the last backstop.
const listenLife = 2 * time.Minute

// setPdeathsig makes the listener die with the shell that started it, however that shell ends.
// The setting belongs to the calling thread, so the goroutine stays locked to it for good.
func setPdeathsig() {
	runtime.LockOSThread()
	syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0)
	if os.Getppid() == 1 {
		os.Exit(1) // the shell was already gone before the setting took hold
	}
}

func helperListen(path string, stdout io.Writer) int {
	setPdeathsig()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(stdout, "FAIL", err)
		return 1
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if err := openListener(line); err != nil {
			fmt.Fprintf(stdout, "FAIL %s: %v\n", line, err)
			return 1
		}
	}
	fmt.Fprintln(stdout, "READY")
	time.Sleep(listenLife)
	return 0
}

// sockOpts returns a Control function that sets the socket options the line asks for. It runs
// after Go's own defaults and before bind, so its IPV6_V6ONLY setting wins.
func sockOpts(is6, v6only bool, dev string, extra func(fd int) error) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if is6 {
				v := 0
				if v6only {
					v = 1
				}
				if serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, v); serr != nil {
					return
				}
			}
			if dev != "" {
				if serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev); serr != nil {
					return
				}
			}
			if extra != nil {
				serr = extra(int(fd))
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// openListener opens one socket from a helper line "proto addr port v6only dev".
func openListener(line string) error {
	f := strings.Fields(line)
	if len(f) != 5 {
		return errors.New("bad listen line")
	}
	addr, err := netip.ParseAddr(f[1])
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(f[2], 10, 16)
	if err != nil {
		return err
	}
	dev := f[4]
	if dev == "-" {
		dev = ""
	}
	ap := netip.AddrPortFrom(addr, uint16(port)).String()
	is6 := addr.Is6()
	network := f[0] + "4"
	if is6 {
		network = f[0] + "6"
	}
	switch f[0] {
	case "tcp":
		lc := net.ListenConfig{Control: sockOpts(is6, f[3] == "1", dev, nil)}
		ln, err := lc.Listen(context.Background(), network, ap)
		if err != nil {
			return err
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	case "udp":
		pktinfo := func(fd int) error {
			// The echo goes back from the address the datagram was sent to, as a server
			// answering on a wildcard socket must, or the prober would not accept it.
			if is6 {
				if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1); err != nil {
					return err
				}
				if f[3] == "1" {
					return nil
				}
				// A dual-stack socket reports IPv4 datagrams' address only through IP_PKTINFO.
			}
			return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
		}
		lc := net.ListenConfig{Control: sockOpts(is6, f[3] == "1", dev, pktinfo)}
		pc, err := lc.ListenPacket(context.Background(), network, ap)
		if err != nil {
			return err
		}
		go udpEcho(pc.(*net.UDPConn))
	default:
		return errors.New("bad protocol")
	}
	return nil
}

func udpEcho(c *net.UDPConn) {
	buf := make([]byte, 2048)
	oob := make([]byte, 512)
	for {
		n, oobn, _, from, err := c.ReadMsgUDP(buf, oob)
		if err != nil {
			return
		}
		c.WriteMsgUDP(buf[:n], replyOOB(oob[:oobn]), from)
	}
}

// replyOOB turns the packet-info message of a received datagram into one that sends the reply
// from the same local address.
func replyOOB(oob []byte) []byte {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_PKTINFO && len(m.Data) >= syscall.SizeofInet4Pktinfo:
			// struct in_pktinfo: ifindex, spec_dst, addr. Reply from addr, any interface.
			var info [syscall.SizeofInet4Pktinfo]byte
			copy(info[4:8], m.Data[8:12])
			return cmsg(syscall.IPPROTO_IP, syscall.IP_PKTINFO, info[:])
		case m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == syscall.IPV6_PKTINFO && len(m.Data) >= syscall.SizeofInet6Pktinfo:
			var info [syscall.SizeofInet6Pktinfo]byte
			copy(info[0:16], m.Data[0:16])
			return cmsg(syscall.IPPROTO_IPV6, syscall.IPV6_PKTINFO, info[:])
		}
	}
	return nil
}

func cmsg(level, typ int, data []byte) []byte {
	b := make([]byte, syscall.CmsgSpace(len(data)))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = int32(level)
	h.Type = int32(typ)
	h.SetLen(syscall.CmsgLen(len(data)))
	copy(b[syscall.CmsgLen(0):], data)
	return b
}

// probeLine is one probe the prober sends: "id src dst proto port".
type probeLine struct {
	id    int
	src   netip.Addr
	dst   netip.Addr
	proto string
	port  uint16
}

func helperProbe(path string, timeout time.Duration, stdout io.Writer) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var probes []probeLine
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Fields(line)
		if len(f) != 5 {
			fmt.Fprintf(os.Stderr, "bad probe line %q\n", line)
			return 1
		}
		var p probeLine
		var e1, e2, e3, e4 error
		p.id, e1 = strconv.Atoi(f[0])
		p.src, e2 = netip.ParseAddr(f[1])
		p.dst, e3 = netip.ParseAddr(f[2])
		p.proto = f[3]
		port, e4 := strconv.ParseUint(f[4], 10, 16)
		if err := errors.Join(e1, e2, e3, e4); err != nil {
			fmt.Fprintf(os.Stderr, "bad probe line %q: %v\n", line, err)
			return 1
		}
		p.port = uint16(port)
		probes = append(probes, p)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	enc := json.NewEncoder(stdout)
	for _, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := sendProbe(p, timeout)
			mu.Lock()
			enc.Encode(r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return 0
}

// sendProbe sends one probe, once. A retry would be a second packet, and stateful matches
// (-m limit, -m recent, hashlimit) treat a second packet differently from the first, so a
// retry can turn a real drop into "open". On a virtual cable nothing is lost, and every answer
// measured arrives within a millisecond, far inside the timeout.
func sendProbe(p probeLine, timeout time.Duration) Real {
	start := time.Now()
	r := Real{ID: p.id}
	r.Outcome, r.Detail = sendOnce(p, timeout)
	r.MS = time.Since(start).Milliseconds()
	return r
}

func sendOnce(p probeLine, timeout time.Duration) (Outcome, string) {
	is6 := p.dst.Is6()
	freebind := func(fd int) error {
		// The source may be any address of a local route; freebind lets IPv6 bind to it too.
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_FREEBIND, 1); err != nil {
			return err
		}
		// Without RECVERR the kernel holds back ICMP errors it calls soft: a UDP socket
		// ignores network and host unreachable, and a TCP connect over IPv6 ignores every
		// ICMPv6 unreachable (even port unreachable) until its next SYN retry, a second
		// later. The answer did arrive, so the probe must see it at once.
		if is6 {
			return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR, 1)
		}
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_RECVERR, 1)
	}
	dup := -1
	keep := func(fd int) error {
		if err := freebind(fd); err != nil {
			return err
		}
		// A copy of the socket outlives Go closing it after a failed connect, so the
		// handshake counters can still be read.
		var err error
		dup, err = syscall.Dup(fd)
		return err
	}
	d := net.Dialer{Timeout: timeout, Control: sockOpts(false, false, "", freebind)}
	dst := netip.AddrPortFrom(p.dst, p.port).String()
	switch p.proto {
	case "tcp":
		d.Control = sockOpts(false, false, "", keep)
		d.LocalAddr = &net.TCPAddr{IP: p.src.AsSlice()}
		c, err := d.Dial(tcpNet(is6), dst)
		defer func() {
			if dup >= 0 {
				syscall.Close(dup)
			}
		}()
		if err == nil {
			c.Close()
			return OutOpen, ""
		}
		// The connect can fail after the handshake completed: a rule that rejects the
		// second packet (our ACK, which is ESTABLISHED) answers so fast that its error
		// overwrites the success before Go reads it. The first packet was answered by a
		// program, so that is open; the lab, like the engine, judges the first packet.
		if dup >= 0 && handshakeDone(dup) {
			return OutOpen, "handshake completed, then " + firstLine(err.Error())
		}
		return classify(err)
	case "udp":
		d.LocalAddr = &net.UDPAddr{IP: p.src.AsSlice()}
		c, err := d.Dial(udpNet(is6), dst)
		if err != nil {
			return OutError, err.Error()
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(timeout))
		if _, err := c.Write([]byte("seaward lab probe")); err != nil {
			return classify(err)
		}
		buf := make([]byte, 64)
		if _, err := c.Read(buf); err != nil {
			return classify(err)
		}
		return OutOpen, ""
	}
	return OutError, "bad protocol " + p.proto
}

// handshakeDone says whether the socket sent more than its SYN without retransmitting, which
// means the SYN-ACK came back and the kernel answered it with an ACK.
func handshakeDone(fd int) bool {
	var info [232]byte
	n := uint32(len(info))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.IPPROTO_TCP, syscall.TCP_INFO,
		uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&n)), 0)
	// struct tcp_info: tcpi_total_retrans at offset 100, tcpi_segs_out at offset 136.
	if e != 0 || n < 140 {
		return false
	}
	retrans := binary.NativeEndian.Uint32(info[100:104])
	segsOut := binary.NativeEndian.Uint32(info[136:140])
	return segsOut-retrans >= 2
}

func tcpNet(is6 bool) string {
	if is6 {
		return "tcp6"
	}
	return "tcp4"
}

func udpNet(is6 bool) string {
	if is6 {
		return "udp6"
	}
	return "udp4"
}

// classify turns a socket error into an outcome. Every ICMP error a firewall can send, and a TCP
// reset, is "refused": something answered. A timeout is "silent". Anything else is a lab fault.
func classify(err error) (Outcome, string) {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return OutSilent, ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EACCES,
			syscall.EHOSTDOWN, syscall.ENONET, syscall.EPROTO, syscall.ECONNRESET:
			return OutRefused, errno.Error()
		}
	}
	return OutError, err.Error()
}
