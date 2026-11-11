package engine

import "strings"

// Deciding is the step a reader is shown as "what decided it": for a stopped packet the rule or
// policy that stopped it, for one let through the last filter rule or policy that accepted it.
// It is nil when nothing in the rules had a say.
func (r Result) Deciding() *Step {
	switch r.Class {
	case Filtered, Rejected:
		for i := len(r.Steps) - 1; i >= 0; i-- {
			if r.Steps[i].Decisive {
				return &r.Steps[i]
			}
		}
		return nil
	case Open, Closed, Forwarded:
		for i := len(r.Steps) - 1; i >= 0; i-- {
			s := &r.Steps[i]
			if (s.Kind == StepRule && s.Effect == "accept") || (s.Kind == StepPolicy && strings.HasPrefix(s.Effect, "policy accept")) {
				return s
			}
		}
	}
	return nil
}

// Rewrite is the step that changed the packet's destination, or nil.
func (r Result) Rewrite() *Step {
	for i := range r.Steps {
		if strings.HasPrefix(r.Steps[i].Effect, "destination becomes") {
			return &r.Steps[i]
		}
	}
	return nil
}
