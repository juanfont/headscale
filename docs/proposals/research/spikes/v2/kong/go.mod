module spike/kong

go 1.27.3

require (
	github.com/alecthomas/kong v1.17.0
	spike/kit v0.0.0
	tailscale.com v1.105.0-pre.0.20261028221719-f7c1b8e52600
)

replace spike/kit => ../../kit-v2
