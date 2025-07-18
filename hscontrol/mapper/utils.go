package mapper

import "tailscale.com/tailcfg"

// mergePatch takes the current patch and a newer patch
// and override any field that has changed.
func mergePatch(currPatch, newPatch *tailcfg.PeerChange) {
	if newPatch.DERPRegion != 0 {
		currPatch.DERPRegion = newPatch.DERPRegion
	}

	if newPatch.Cap != 0 {
		currPatch.Cap = newPatch.Cap
	}

	if newPatch.CapMap != nil {
		currPatch.CapMap = newPatch.CapMap
	}

	if newPatch.Endpoints != nil {
		currPatch.Endpoints = newPatch.Endpoints
	}

	if newPatch.Key != nil {
		currPatch.Key = newPatch.Key
	}

	if newPatch.KeySignature != nil {
		currPatch.KeySignature = newPatch.KeySignature
	}

	if newPatch.DiscoKey != nil {
		currPatch.DiscoKey = newPatch.DiscoKey
	}

	if newPatch.Online != nil {
		currPatch.Online = newPatch.Online
	}

	if newPatch.LastSeen != nil {
		currPatch.LastSeen = newPatch.LastSeen
	}

	if newPatch.KeyExpiry != nil {
		currPatch.KeyExpiry = newPatch.KeyExpiry
	}
}
