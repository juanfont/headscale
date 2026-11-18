// Package typed is a sketch: a typed layer on top of the string core
// (spike/cmdline). It shows that the compiler can check the input of a
// command; it is not the final API.
package typed

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"spike/cmdline"
)

// Parser reads one word as a T. netip.ParsePrefix and time.ParseDuration
// already have this shape.
type Parser[T any] func(string) (T, error)

// Value is implemented by a type that reads itself.
type Value[T any] interface{ Parse(string) (T, error) }

// Input is implemented by the input struct of a command.
type Input interface{ Bind(b *Binder) }

// Opt records whether a flag was given.
type Opt[T any] struct {
	v  T
	ok bool
}

func (o Opt[T]) Get() (T, bool) { return o.v, o.ok }

type slot struct {
	name string
	set  func(string) error
}

// Binder collects the flags and arguments of one input struct.
type Binder struct {
	flags []cmdline.Flag
	set   map[string]func(string) error
	args  []slot
}

func bind[T any](p *T, parse Parser[T]) func(string) error {
	return func(s string) error {
		v, err := parse(s)
		if err == nil {
			*p = v
		}
		return err
	}
}

// Flag binds a flag to a field whose type reads itself.
func (b *Binder) Flag[T Value[T]](p *T, name, help string) {
	b.FlagFunc(p, name, Self[T](), help)
}

// FlagFunc binds a flag to a field with a parse function.
func (b *Binder) FlagFunc[T any](p *T, name string, parse Parser[T], help string) {
	_, isBool := any(p).(*bool)
	b.flags = append(b.flags, cmdline.Flag{Name: name, Help: help, Bool: isBool})
	b.set[name] = bind(p, parse)
}

// Arg binds the next positional to a field whose type reads itself.
func (b *Binder) Arg[T Value[T]](p *T, name string) { b.ArgFunc(p, name, Self[T]()) }

// ArgFunc binds the next positional to a field with a parse function.
func (b *Binder) ArgFunc[T any](p *T, name string, parse Parser[T]) {
	b.args = append(b.args, slot{name, bind(p, parse)})
}

// Self is the parser that a type carries itself.
func Self[T Value[T]]() Parser[T] {
	return func(s string) (T, error) { var z T; return z.Parse(s) }
}

func String(s string) (string, error) { return s, nil }

func Bool(s string) (bool, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("takes true or false, not %q", s)
}

// List reads one comma-separated word.
func List[T any](p Parser[T]) Parser[[]T] {
	return func(s string) ([]T, error) {
		var out []T
		for _, w := range strings.Split(s, ",") {
			v, err := p(w)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
}

// Given makes a parser for a field that records whether it was given.
func Given[T any](p Parser[T]) Parser[Opt[T]] {
	return func(s string) (Opt[T], error) { v, err := p(s); return Opt[T]{v, err == nil}, err }
}

// Command is one leaf. In is its input struct.
type Command[In any] struct {
	Name, Help string
	Aliases    []string
	Run        func(ctx context.Context, in In) error
}

// Node is a command or a group in the tree.
type Node struct {
	cmd  *cmdline.Command
	exec map[*cmdline.Command]func(context.Context, *cmdline.Match) error
}

// ValueError is a typed usage error from the typed layer.
type ValueError struct {
	Path []string
	Name string // flag or argument
	Word string
	At   int
	Err  error
}

func (e *ValueError) Error() string {
	return fmt.Sprintf("%s %q at %d: %v", e.Name, e.Word, e.At, e.Err)
}

// New makes a leaf. The compiler refuses an In without a Bind method.
func New[In any, P interface {
	*In
	Input
}](c Command[In]) Node {
	fresh := func() (*In, *Binder) {
		in, b := new(In), &Binder{set: map[string]func(string) error{}}
		P(in).Bind(b)
		return in, b
	}
	_, b := fresh()
	cmd := &cmdline.Command{Name: c.Name, Aliases: c.Aliases, Help: c.Help, Flags: b.flags, Args: make([]cmdline.Completer, len(b.args))}
	return Node{cmd, map[*cmdline.Command]func(context.Context, *cmdline.Match) error{
		cmd: func(ctx context.Context, m *cmdline.Match) error {
			in, b := fresh()
			var first *ValueError // the first mistake on the line wins
			note := func(name, word string, at int, err error) {
				if err != nil && (first == nil || at < first.At) {
					first = &ValueError{m.Path, name, word, at, err}
				}
			}
			seen := map[string]bool{}
			for _, g := range m.Flags {
				if seen[g.Name] {
					note("--"+g.Name, g.Value, g.At, errors.New("given twice"))
				}
				seen[g.Name] = true
				note("--"+g.Name, g.Value, g.At, b.set[g.Name](g.Value))
			}
			if len(m.Args) != len(b.args) {
				return &ValueError{Path: m.Path, Err: fmt.Errorf("takes %d arguments, got %d", len(b.args), len(m.Args))}
			}
			for i, a := range m.Args {
				note("<"+b.args[i].name+">", a, m.ArgAt[i], b.args[i].set(a))
			}
			if first != nil {
				return first
			}
			return c.Run(ctx, *in)
		},
	}}
}

// Group makes a command that only has subcommands.
func Group(name, help string, children ...Node) Node {
	n := Node{&cmdline.Command{Name: name, Help: help}, map[*cmdline.Command]func(context.Context, *cmdline.Match) error{}}
	for _, c := range children {
		n.cmd.Commands = append(n.cmd.Commands, c.cmd)
		for k, v := range c.exec {
			n.exec[k] = v
		}
	}
	return n
}

// Run reads argv and calls the Run of the command reached.
func Run(ctx context.Context, root Node, argv []string) error {
	m, err := cmdline.Parse(root.cmd, argv)
	if err != nil {
		return err
	}
	exec, ok := root.exec[m.Command]
	if !ok {
		return fmt.Errorf("help of %q", strings.Join(m.Path, " "))
	}
	return exec(ctx, m)
}
