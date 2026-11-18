module spike/cobra

go 1.27.3

require (
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.1.0
	spike/kit v0.0.0
)

require github.com/inconshreveable/mousetrap v1.1.0 // indirect

replace spike/kit => ../../kit-v2
