module probe

go 1.24

require (
	github.com/alecthomas/kong v1.17.0
	github.com/peterbourgon/ff/v4 v4.0.0
	github.com/urfave/cli/v3 v3.14.0
)

replace (
	github.com/alecthomas/kong => ../srclinks/kong
	github.com/peterbourgon/ff/v4 => ../srclinks/ff
	github.com/urfave/cli/v3 => ../srclinks/urfave-cli
)
