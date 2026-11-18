package headscale

import (
	"reflect"
	"strings"

	"spike/cmdline"
	"spike/kit"
)

// Describe gives the tree as the kit describes one, read from the
// library's data alone: what a help or man page generator has to work with.
// The flat order is the kit's: a group before its commands.
func Describe(t *Tree) []kit.Command {
	var out []kit.Command
	var walk func(*cmdline.Info)
	walk = func(c *cmdline.Info) {
		k := kit.Command{Path: c.Path, Aliases: c.Aliases, Short: c.Help, Leaf: len(c.Commands) == 0}
		if len(c.Path) == 0 {
			k.Path = nil
		}
		for _, f := range c.Flags {
			fl := kit.Flag{Name: f.Name, Short: f.Short, Kind: kit.String, Help: f.Help, List: f.List}
			switch {
			case f.Bool:
				fl.Kind = kit.Bool
			case f.Repeat:
				fl.Kind = kit.Strings
			}
			fl.Global = f.Name == "output" || f.Name == "config"
			fl.Signs = strings.HasPrefix(f.Type.Name(), "Column[")
			fl.File, fl.Values = offers(c, f.Type)
			k.Flags = append(k.Flags, fl)
		}
		for _, a := range c.Args {
			arg := kit.Arg{Name: a.Name, Optional: a.Optional, List: a.List}
			arg.File, arg.Values = offers(c, a.Type)
			k.Args = append(k.Args, arg)
		}
		out = append(out, k)
		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(t.Root())
	return out
}

// offers asks a type what Tab would get for it.
func offers(c *cmdline.Info, t reflect.Type) (file bool, words []string) {
	comp, ok := reflect.Zero(t).Interface().(cmdline.Completer)
	if !ok {
		return false, nil
	}
	words, dir := comp.Complete(&cmdline.Line{Command: c}, "")
	return dir&cmdline.NoFiles == 0, words
}
