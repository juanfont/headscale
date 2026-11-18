module spike/urfave

go 1.27.3

require (
	github.com/urfave/cli/v3 v3.14.0
	spike/kit v0.0.0
)

require tailscale.com v1.105.0-pre.0.20261028221719-f7c1b8e52600 // indirect

replace spike/kit => ../../kit
