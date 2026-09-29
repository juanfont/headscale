package v2

import (
	"fmt"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
)

// BenchmarkIdPGroupMembers measures resolving one identity-provider group
// reference against a large directory: 5000 users with 100 groups each.
func BenchmarkIdPGroupMembers(b *testing.B) {
	users := make(types.Users, 5000)
	for i := range users {
		users[i].ID = uint(i + 1)
		for g := range 100 {
			users[i].Memberships = append(users[i].Memberships, types.UserGroup{
				Group: types.Group{Name: fmt.Sprintf("group-%03d@example.com", (g*7+i)%400)},
			})
		}
	}

	b.ReportAllocs()

	for b.Loop() {
		_ = idpGroupMembers("group-042@example.com", users)
	}
}
