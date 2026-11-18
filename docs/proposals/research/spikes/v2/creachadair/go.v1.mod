module spike/creachadair

go 1.27.3

require (
	github.com/creachadair/command v0.2.13
	spike/kit v0.0.0
	tailscale.com v1.105.0-pre.0.20261028221719-f7c1b8e52600
)

require github.com/creachadair/mds v0.31.0 // indirect

replace spike/kit => ../../kit
