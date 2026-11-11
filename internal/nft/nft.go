// Package nft reads "nft -j list ruleset" output into the rules model.
package nft

import (
	"errors"

	"github.com/gallowforge/seaward/internal/rules"
)

// ParseJSON parses one "nft -j list ruleset" document. Skip names tables to leave out, as
// "family name" ("ip filter"): the ones iptables-save already described in full.
func ParseJSON(data []byte, skip map[string]bool) (*rules.Ruleset, error) {
	return nil, errors.New("nft: not written yet")
}
