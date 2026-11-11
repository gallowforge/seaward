//go:build !unix

package main

import "errors"

// stepDown has nothing to do where there is no root to give up; a snapshot is only taken on Linux.
func stepDown(uid, gid int) error { return errors.ErrUnsupported }
