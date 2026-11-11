//go:build !linux

package main

import (
	"os"
	"strconv"
)

// columns: away from Linux the shell's own word is taken, when it gives one.
func columns(*os.File) int {
	n, _ := strconv.Atoi(os.Getenv("COLUMNS"))
	return n
}
