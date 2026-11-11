// Package ipt reads iptables-save, ip6tables-save and ipset save output into the rules model.
package ipt

import (
	"errors"

	"github.com/gallowforge/seaward/internal/rules"
)

// Options says what the text is.
type Options struct {
	Family string // "ip" for iptables-save, "ip6" for ip6tables-save
	Legacy bool   // true when it came from the legacy (x_tables) backend
	// SetDims gives, for each ipset by name, the dimensions of its type as ParseIPSet returned
	// them: hash:ip,port is ["ip", "port"].
	SetDims map[string][]string
}

// ParseSave parses the output of iptables-save or ip6tables-save. Notes are plain sentences about
// things it saw and could not represent as a whole (a table marked incompatible, say).
func ParseSave(text string, o Options) (tables []*rules.Table, notes []string, err error) {
	return nil, nil, errors.New("ipt: not written yet")
}

// ParseIPSet parses the output of "ipset save". Sets are keyed by rules.SetKey("", "", name).
func ParseIPSet(text string) (sets map[string]*rules.Set, dims map[string][]string, notes []string, err error) {
	return nil, nil, nil, errors.New("ipt: not written yet")
}
