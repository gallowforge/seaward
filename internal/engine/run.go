package engine

import (
	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// Run walks one probe through the rules and says how it ends.
func Run(rs *rules.Ruleset, h *host.Host, p Probe) Result {
	return Result{Class: Undecided, Unknowns: []string{"the engine is not written yet"}}
}
