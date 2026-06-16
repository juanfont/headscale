package matcher

// MatchFromStrings builds a [Match] from raw source and destination
// strings. Unparseable entries are silently dropped (fail-open): the
// resulting [Match] is narrower than the input described, but never
// wider. Callers that need strict validation should pre-validate
// their inputs via [util.ParseIPSet].
func MatchFromStrings(sources, destinations []string) Match {
	return Match{
		srcs:  buildIPSet(sources),
		dests: buildIPSet(destinations),
	}
}
