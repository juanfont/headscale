package own

import "errors"

type Parsed struct {
	Path   []string
	Node   *Node // a group when no leaf was named: the layer prints help
	Values map[string][]string
	Args   []string
}

// Dispatch walks argv down the tree. Before the leaf only the root's flags
// (-c, -o, -h) are read; they are handed to the leaf again, so a leaf without
// --output still refuses -o (D3).
func Dispatch(root *Node, argv []string, parse Parser) (*Parsed, error) {
	node, path, rest := root, []string{}, argv
	var pre []string
	for !node.Leaf() {
		vals, r, err := parse(root.Flags, rest, true)
		if err != nil {
			return nil, withPath(err, path)
		}
		pre = append(pre, rest[:len(rest)-len(r)]...)
		if len(r) == 0 {
			return &Parsed{Path: path, Node: node, Values: vals}, nil
		}
		next := node.Child(r[0])
		if next == nil {
			return nil, &UnknownCommandError{Path: path, Word: r[0]}
		}
		node, path, rest = next, append(path, next.Name), r[1:]
	}
	vals, args, err := parse(node.Flags, append(pre, rest...), false)
	if err != nil {
		return nil, withPath(err, path)
	}
	return &Parsed{Path: path, Node: node, Values: vals, Args: args}, nil
}

func withPath(err error, path []string) error {
	var uf *UnknownFlagError
	var mv *MissingValueError
	var bv *BadValueError
	switch {
	case errors.As(err, &uf):
		uf.Path = path
	case errors.As(err, &mv):
		mv.Path = path
	case errors.As(err, &bv):
		bv.Path = path
	}
	return err
}
