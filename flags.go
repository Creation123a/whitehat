package main

import "flag"

type opsFlags struct {
	PublicRPC     bool
	AnonTeam      bool
	NoLegal       bool
	TrackingStale bool
}

func registerOpsFlags(fs *flag.FlagSet) *opsFlags {
	o := &opsFlags{}
	fs.BoolVar(&o.PublicRPC, "op-public-rpc", false,
		"O-1: operator relies on public RPC only")
	fs.BoolVar(&o.AnonTeam, "op-anon-team", false,
		"O-2: operator team is anonymous")
	fs.BoolVar(&o.NoLegal, "op-no-legal", false,
		"O-3: operator has no legal entity")
	fs.BoolVar(&o.TrackingStale, "op-tracking-stale", false,
		"O-4: operator tracking is obsolete")
	return o
}

func (o *opsFlags) toPresent() map[string]bool {
	m := make(map[string]bool, 4)
	if o.PublicRPC {
		m["O-1"] = true
	}
	if o.AnonTeam {
		m["O-2"] = true
	}
	if o.NoLegal {
		m["O-3"] = true
	}
	if o.TrackingStale {
		m["O-4"] = true
	}
	return m
}
