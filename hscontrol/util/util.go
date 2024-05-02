package util

import "tailscale.com/util/cmpver"

func TailscaleVersionNewerOrEqual(minimum, toCheck string) bool {
	if cmpver.Compare(minimum, toCheck) <= 0 ||
		toCheck == "unstable" ||
		toCheck == "head" {
		return true
	}

	return false
}
