package integration

import (
	"testing"
)

func pingAllHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
	t.Helper()
	success := 0

	for _, client := range clients {
		for _, addr := range addrs {
			err := client.Ping(addr)
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", addr, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	return success
}

// pingAllNegativeHelper is intended to have 1 or more nodes timeing out from the ping,
// it counts failures instead of successes.
// func pingAllNegativeHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
// 	t.Helper()
// 	failures := 0
//
// 	timeout := 100
// 	count := 3
//
// 	for _, client := range clients {
// 		for _, addr := range addrs {
// 			err := client.Ping(
// 				addr,
// 				tsic.WithPingTimeout(time.Duration(timeout)*time.Millisecond),
// 				tsic.WithPingCount(count),
// 			)
// 			if err != nil {
// 				failures++
// 			}
// 		}
// 	}
//
// 	return failures
// }
