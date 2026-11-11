package main

import (
	"os"
	"syscall"
	"unsafe"
)

// columns asks the kernel how wide the terminal is. 0 means it would not say.
func columns(f *os.File) int {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0
	}
	return int(ws.Col)
}
