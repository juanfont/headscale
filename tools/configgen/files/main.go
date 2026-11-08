// Command files writes the files generated from the configuration schema
// of hscontrol/config: `files <root>` writes nix/options.generated.nix
// below the repository root. It is not part of configgen, which stays
// standard library only so its table regenerates when the committed one
// does not compile.
//
// `files -load <file>` prints the file as config.Load reads it, for the
// NixOS options check to compare with the values it was written from.
package main

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/juanfont/headscale/hscontrol/config"
)

func main() {
	var err error

	switch {
	case len(os.Args) == 3 && os.Args[1] == "-load":
		err = load(os.Stdout, os.Args[2])
	case len(os.Args) == 2:
		err = write(os.Args[1])
	default:
		log.Fatal("usage: files <repository root> | files -load <config file>")
	}

	if err != nil {
		log.Fatal(err)
	}
}

// load writes path, as config.Load reads it, to w as YAML without the
// client-only keys, which no NixOS option sets.
func load(w io.Writer, path string) error {
	l, err := config.Load(path, true, nil)
	for _, warning := range l.Warnings {
		log.Print(warning)
	}

	if err != nil {
		return err
	}

	out, err := config.GenerateExample(l.Config, config.ExampleOptions{OmitClientOnly: true})
	if err != nil {
		return err
	}

	_, err = w.Write(out)

	return err
}

// write writes every generated file below root.
func write(root string) error {
	nix, err := config.GenerateNixOptions(nil)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(root, "nix", "options.generated.nix"), nix, 0o600)
}
