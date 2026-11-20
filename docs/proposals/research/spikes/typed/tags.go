package typed

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"spike/cmdline"
)

// This file is the other sketch: struct tags and reflection (choice 1B).

type readFn func(string) (reflect.Value, error)

var registry = map[reflect.Type]readFn{}

// Register gives the tag reader a parser for a type that has no Parse
// method of its own. A tag cannot hold a function, so the type decides.
func Register[T any](p Parser[T]) {
	registry[reflect.TypeFor[T]()] = func(s string) (reflect.Value, error) {
		v, err := p(s)
		return reflect.ValueOf(v), err
	}
}

func init() { Register(String); Register(Bool) }

type lateFn func(context.Context, string) (reflect.Value, error)

var late = map[reflect.Type]lateFn{}

// RegisterLate gives a reader that needs more than the word, such as a
// lookup on a server. It runs after every plain value is read.
func RegisterLate[T any](p func(context.Context, string) (T, error)) {
	late[reflect.TypeFor[T]()] = func(ctx context.Context, s string) (reflect.Value, error) {
		v, err := p(ctx, s)
		return reflect.ValueOf(v), err
	}
}

func keep(s string) (reflect.Value, error) { return reflect.ValueOf(s), nil }

type optional interface {
	elem() reflect.Type
	give(v any)
}

func (o *Opt[T]) elem() reflect.Type { return reflect.TypeFor[T]() }
func (o *Opt[T]) give(v any)         { o.v, o.ok = v.(T), true }

var (
	errType  = reflect.TypeFor[error]()
	textType = reflect.TypeFor[encoding.TextUnmarshaler]()
)

func reader(t reflect.Type) (readFn, error) {
	if r, ok := registry[t]; ok {
		return r, nil
	}
	if reflect.PointerTo(t).Implements(textType) {
		return func(s string) (reflect.Value, error) {
			v := reflect.New(t)
			err := v.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(s))
			return v.Elem(), err
		}, nil
	}
	if m, ok := t.MethodByName("Parse"); ok && m.Type.NumIn() == 2 && m.Type.In(1).Kind() == reflect.String &&
		m.Type.NumOut() == 2 && m.Type.Out(0) == t && m.Type.Out(1) == errType {
		return func(s string) (reflect.Value, error) {
			out := m.Func.Call([]reflect.Value{reflect.Zero(t), reflect.ValueOf(s)})
			err, _ := out[1].Interface().(error)
			return out[0], err
		}, nil
	}
	if t.Kind() == reflect.Slice {
		el, err := reader(t.Elem())
		if err != nil {
			return nil, err
		}
		return func(s string) (reflect.Value, error) {
			out := reflect.MakeSlice(t, 0, 1)
			for _, w := range strings.Split(s, ",") {
				v, err := el(w)
				if err != nil {
					return out, err
				}
				out = reflect.Append(out, v)
			}
			return out, nil
		}, nil
	}
	return nil, fmt.Errorf("%s cannot be read", t)
}

type field struct {
	index int
	name  string
	read  readFn
	opt   bool
	late  lateFn
}

// Usage is the usage line, made from the struct: no second copy to keep right.
func usage(path []string, args []field) string {
	for _, a := range args {
		if a.opt {
			path = append(path, "["+a.name+"]")
		} else {
			path = append(path, "<"+a.name+">")
		}
	}
	return strings.Join(path, " ")
}

// NewTagged makes a leaf from struct tags. A wrong struct stops the program
// here, when it starts; the compiler does not see it.
func NewTagged[In any](c Command[In]) Node {
	t := reflect.TypeFor[In]()
	cmd := &cmdline.Command{Name: c.Name, Aliases: c.Aliases, Help: c.Help}
	flags := map[string]field{}
	var args []field
	for i := range t.NumField() {
		f, ft := t.Field(i), t.Field(i).Type
		fl := field{index: i}
		if o, ok := reflect.New(ft).Interface().(optional); ok {
			ft, fl.opt = o.elem(), true
		}
		r, err := reader(ft)
		if l, ok := late[ft]; ok {
			r, err, fl.late = keep, nil, l
		}
		if err != nil {
			panic(fmt.Sprintf("%s: field %s: %v", c.Name, f.Name, err))
		}
		fl.read = r
		switch {
		case f.Tag.Get("arg") != "":
			fl.name = f.Tag.Get("arg")
			args = append(args, fl)
		case f.Tag.Get("flag") != "":
			fl.name = f.Tag.Get("flag")
			flags[fl.name] = fl
			cmd.Flags = append(cmd.Flags, cmdline.Flag{Name: fl.name, Help: f.Tag.Get("help"), Bool: ft.Kind() == reflect.Bool})
		default:
			panic(fmt.Sprintf("%s: field %s has no arg or flag tag", c.Name, f.Name))
		}
	}
	cmd.Args = make([]cmdline.Completer, len(args))
	return Node{cmd, map[*cmdline.Command]func(context.Context, *cmdline.Match) error{
		cmd: func(ctx context.Context, m *cmdline.Match) error {
			in := reflect.New(t).Elem()
			var first *ValueError
			type pending struct {
				fl   field
				name string
				word string
				at   int
			}
			var lookups []pending
			put := func(fl field, name, word string, at int, err error) {
				var v reflect.Value
				if err == nil {
					v, err = fl.read(word)
				}
				switch {
				case err != nil && (first == nil || at < first.At):
					first = &ValueError{m.Path, name, word, at, err}
				case err == nil && fl.late != nil:
					lookups = append(lookups, pending{fl, name, word, at})
				case err == nil && fl.opt:
					in.Field(fl.index).Addr().Interface().(optional).give(v.Interface())
				case err == nil:
					in.Field(fl.index).Set(v)
				}
			}
			seen := map[string]bool{}
			for _, g := range m.Flags {
				var err error
				if seen[g.Name] {
					err = errors.New("given twice")
				}
				seen[g.Name] = true
				put(flags[g.Name], "--"+g.Name, g.Value, g.At, err)
			}
			if len(m.Args) != len(args) {
				return &ValueError{Path: m.Path, Err: fmt.Errorf("usage: %s", usage(append([]string{"prog"}, m.Path...), args))}
			}
			for i, a := range m.Args {
				put(args[i], "<"+args[i].name+">", a, m.ArgAt[i], nil)
			}
			if first != nil {
				return first
			}
			for _, l := range lookups { // only when the whole line is right
				v, err := l.fl.late(ctx, l.word)
				if err != nil {
					return &ValueError{m.Path, l.name, l.word, l.at, err}
				}
				in.Field(l.fl.index).Set(v)
			}
			return c.Run(ctx, in.Interface().(In))
		},
	}}
}
