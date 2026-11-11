//go:build unix

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// stepDown gives up root for good and carries on as the given user: their groups, then their
// group, then their id, in the only order that works. Nothing after it can get root back.
func stepDown(uid, gid int) error {
	groups := []int{gid}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		if ids, err := u.GroupIds(); err == nil {
			for _, s := range ids {
				if g, err := strconv.Atoi(s); err == nil && g != gid {
					groups = append(groups, g)
				}
			}
		}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("still not user %d", uid)
	}
	return nil
}
