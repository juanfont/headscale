module spike/diff

go 1.27.3

require (
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.1.0
	spike/cobra v0.0.0
	spike/kit v0.0.0
	spike/own-grammar v0.0.0
	spike/own-pflag v0.0.0
)

require github.com/inconshreveable/mousetrap v1.1.0 // indirect

replace (
	spike/kit => ./kit
	spike/own-grammar => ../v2/own-grammar
	spike/own-pflag => ../v2/own-pflag
	spike/cobra => ../v2/cobra
)
