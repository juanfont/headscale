package own

import (
	"errors"
	"fmt"
	"io"
	"strings"

	cs "probe-own/cobrascripts"
)

// Complete answers cobra's __complete protocol from the tree: words typed so
// far, and cur, the word under the cursor. It reads no config and no network.
func Complete(root *Node, words []string, cur string, desc bool) ([]string, int) {
	node, rest := root, words
	for !node.Leaf() {
		_, r, err := OwnParse(root.Flags, rest, true)
		var mv *MissingValueError
		if errors.As(err, &mv) { // "headscale -o <TAB>"
			return values(lookupTyped(root.Flags, mv.Flag), cur)
		}
		if err != nil || len(r) == 0 {
			break
		}
		next := node.Child(r[0])
		if next == nil {
			return nil, cs.ShellCompDirectiveNoFileComp
		}
		node, rest = next, r[1:]
	}

	// A value for the flag in the previous word, or after "=" in this one.
	if n := len(rest); n > 0 && !strings.Contains(rest[n-1], "=") {
		if f := lookupTyped(node.Flags, rest[n-1]); f != nil && f.Kind != Bool {
			return values(f, cur)
		}
	}
	if strings.HasPrefix(cur, "-") && strings.Contains(cur, "=") {
		name, val, _ := strings.Cut(cur, "=")
		return values(lookupTyped(node.Flags, name), val)
	}

	var out []string
	add := func(word, help string) {
		if strings.HasPrefix(word, cur) {
			if desc && help != "" {
				word += "\t" + help
			}
			out = append(out, word)
		}
	}
	if strings.HasPrefix(cur, "-") {
		for _, f := range node.Flags {
			add("--"+f.Long, f.Help)
			if f.Short != "" && cur == "-"+f.Short {
				add("-"+f.Short, f.Help)
			}
		}
		return out, cs.ShellCompDirectiveNoFileComp
	}
	if !node.Leaf() {
		for _, c := range node.Children {
			add(c.Name, c.Short)
		}
		return out, cs.ShellCompDirectiveNoFileComp
	}
	if node.Files {
		return nil, cs.ShellCompDirectiveDefault
	}
	for _, w := range node.ArgWords {
		add(w, "")
	}
	return out, cs.ShellCompDirectiveNoFileComp
}

func lookupTyped(flags []Flag, typed string) *Flag {
	switch {
	case strings.HasPrefix(typed, "--"):
		return lookup(flags, typed[2:], false)
	case strings.HasPrefix(typed, "-") && len(typed) == 2:
		return lookup(flags, typed[1:], true)
	}
	return nil
}

// values completes a flag value. A comma list completes its last item and
// keeps what is before it; a +/- prefix is kept for signed lists.
func values(f *Flag, cur string) ([]string, int) {
	if f == nil {
		return nil, cs.ShellCompDirectiveNoFileComp
	}
	head, item := "", cur
	if f.Comma {
		if i := strings.LastIndex(cur, ","); i >= 0 {
			head, item = cur[:i+1], cur[i+1:]
		}
	}
	sign := ""
	if f.Signed && item != "" && (item[0] == '+' || item[0] == '-') {
		sign, item = item[:1], item[1:]
	}
	var out []string
	for _, v := range f.Values {
		if strings.HasPrefix(v, item) && !strings.Contains(","+head, ","+v+",") {
			out = append(out, head+sign+v)
		}
	}
	dir := cs.ShellCompDirectiveNoFileComp
	if f.Comma || f.Kind == Repeat {
		dir |= cs.ShellCompDirectiveNoSpace // room for "," or an operator
	}
	return out, dir
}

// Serve is the hidden __complete entry point.
func Serve(w io.Writer, root *Node, args []string, desc bool) {
	if len(args) == 0 {
		args = []string{""}
	}
	out, dir := Complete(root, args[:len(args)-1], args[len(args)-1], desc)
	for _, o := range out {
		fmt.Fprintln(w, o)
	}
	fmt.Fprintf(w, ":%d\n", dir)
}
