package matcher

import (
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
)

// MatchFromStrings builds a [Match] from raw source and destination
// strings. Unparseable entries are silently dropped (fail-open): the
// resulting [Match] is narrower than the input described, but never
// wider. Callers that need strict validation should pre-validate
// their inputs via [util.ParseIPSet].
func MatchFromStrings(sources, destinations []string) Match {
	srcs := new(netipx.IPSetBuilder)
	dests := new(netipx.IPSetBuilder)

	for _, srcIP := range sources {
		set, _ := util.ParseIPSet(srcIP, nil)

		srcs.AddSet(set)
	}

	for _, dest := range destinations {
		set, _ := util.ParseIPSet(dest, nil)

		dests.AddSet(set)
	}

	srcsSet, _ := srcs.IPSet()
	destsSet, _ := dests.IPSet()

	match := Match{
		srcs:  srcsSet,
		dests: destsSet,
	}

	return match
}
