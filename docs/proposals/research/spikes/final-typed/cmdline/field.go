package cmdline

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"spike/cmdline/internal/reader"
)

// Opt is a value that may be left out. As a flag it records whether the
// flag was given, so --name "" differs from no --name; as an argument it
// makes the argument optional.
type Opt[T any] struct {
	v  T
	ok bool
}

// Some returns an Opt that was given v, for code that fills an input struct
// by hand.
func Some[T any](v T) Opt[T] { return Opt[T]{v, true} }

// Get returns the value and whether it was given.
func (o Opt[T]) Get() (T, bool) { return o.v, o.ok }

func (o *Opt[T]) set(v reflect.Value) { o.v, o.ok = v.Interface().(T), true }
func (*Opt[T]) one() reflect.Type     { return reflect.TypeFor[T]() }

// Repeat is a flag that may be given more than once: each occurrence adds
// one T. Every other flag is given once; a list is one comma-separated
// value ([]T).
type Repeat[T any] []T

func (Repeat[T]) one() reflect.Type { return reflect.TypeFor[T]() }

type (
	optional interface {
		set(reflect.Value)
		one() reflect.Type
	}
	repeated interface{ one() reflect.Type }
)

// Path is a file path. Tab offers file names for it.
type Path string

// UnmarshalText takes any word.
func (p *Path) UnmarshalText(b []byte) error { *p = Path(b); return nil }

// Complete lets the shell offer file names.
func (Path) Complete(*Line, string) ([]string, Directive) { return nil, 0 }

// What a reader of the library says about a word it refuses; UsageError.Err
// holds it.
var (
	ErrBool      = errors.New("not true or false")
	ErrEmpty     = errors.New("the list is empty")
	ErrEmptyItem = errors.New("the list has an empty item")
)

// What Line.Run returns for a line that has no mistake and still does not
// run.
var (
	ErrGroup     = errors.New("cmdline: the line ends at a group, which does not run")
	ErrRan       = errors.New("cmdline: the line has run already")
	ErrNotParsed = errors.New("cmdline: the line is not from Parse")
)

type (
	readFn func(string) (reflect.Value, error)
	lateFn func(context.Context, string) (reflect.Value, error)
)

// Option tells New how to read a type that cannot say so itself.
type Option struct{ apply func(*builder) }

// Reader makes read the reader of every field of type T. It is for a type
// that has no UnmarshalText and is not yours to give one, such as
// time.Duration; it wins over the method when a type has both.
func Reader[T any](read func(string) (T, error)) Option {
	return Option{func(b *builder) {
		b.once(reflect.TypeFor[T]())
		b.readers[reflect.TypeFor[T]()] = func(s string) (reflect.Value, error) {
			v, err := read(s)
			return reflect.ValueOf(&v).Elem(), err
		}
	}}
}

// LateReader makes read the reader of every field of type T, and puts it
// off: Parse keeps the word, and Line.Run calls read with its context once
// the whole line is right. It is for a value that needs more than the word,
// such as a lookup on a server.
func LateReader[T any](read func(ctx context.Context, word string) (T, error)) Option {
	return Option{func(b *builder) {
		b.once(reflect.TypeFor[T]())
		b.late[reflect.TypeFor[T]()] = func(ctx context.Context, s string) (reflect.Value, error) {
			v, err := read(ctx, s)
			return reflect.ValueOf(&v).Elem(), err
		}
	}}
}

func (b *builder) once(t reflect.Type) {
	if b.readers[t] != nil || b.late[t] != nil {
		b.bad("%s has two readers", t)
	}
}

// field is one tagged field of an input struct or of a struct of flags.
type field struct {
	part  reflect.Type // the struct
	index int
	name  string
	short string
	help  string
	def   *string

	// The field's type is elem, or one of []elem, Opt[..] and Repeat[..]
	// around either.
	opt, repeat, list bool
	one               reflect.Type // what one occurrence is read as: elem or []elem
	elem              reflect.Type
	read              readFn
	late              lateFn
}

func (f *field) bool() bool { return !f.list && f.late == nil && f.elem.Kind() == reflect.Bool }

func (f *field) flag() Flag {
	fl := Flag{
		Name: f.name, Short: f.short, Help: f.help, Type: f.elem, Bool: f.bool(),
		List: f.list, Repeat: f.repeat, Optional: f.opt, Late: f.late != nil,
	}
	if f.def != nil {
		fl.Default = *f.def
	}
	return fl
}

func (f *field) low(nodes map[*reader.Command]*node) reader.Flag {
	fl := reader.Flag{Name: f.name, Bool: f.bool(), Repeat: f.repeat, Help: f.help, Complete: f.completer(nodes)}
	for _, r := range f.short {
		fl.Short = r
	}
	return fl
}

var tagKeys = []string{"arg", "flag", "short", "help", "default"}

// fields reads the tags of struct t. Only an input struct holds arguments.
func (b *builder) fields(at string, t reflect.Type, input bool) (flags, args []*field) {
	if t.Kind() != reflect.Struct {
		b.bad("%s: the input type %s is no struct", at, t)
		return nil, nil
	}
	for i := range t.NumField() {
		sf := t.Field(i)
		bad := func(format string, a ...any) {
			b.bad("%s: %s.%s: %s", at, t, sf.Name, fmt.Sprintf(format, a...))
		}
		tags, err := parseTag(sf.Tag)
		if err != nil {
			bad("%v", err)
			continue
		}
		for k := range tags {
			if !slices.Contains(tagKeys, k) {
				bad("unknown tag %q", k)
			}
		}
		arg, isArg := tags["arg"]
		name, isFlag := tags["flag"]
		_, hasShort := tags["short"]
		def, hasDef := tags["default"]
		switch {
		case !sf.IsExported():
			bad("is not exported")
			continue
		case isArg && isFlag:
			bad("has an arg and a flag tag")
			continue
		case !isArg && !isFlag:
			bad("has no arg or flag tag")
			continue
		}
		f := &field{part: t, index: i, name: name, short: tags["short"], help: tags["help"]}
		if err := b.typ(f, sf.Type); err != nil {
			bad("%v", err)
			continue
		}
		if isFlag {
			switch {
			case hasShort && len([]rune(f.short)) != 1:
				bad("short %q is not one letter", f.short)
			case hasDef && (f.opt || f.late != nil):
				bad("an Opt or a late value takes no default")
			case hasDef:
				f.def = &def
				if _, err := f.parse(def); err != nil {
					bad("default %q: %v", def, err)
				}
			}
			flags = append(flags, f)
			continue
		}
		f.name = arg
		switch {
		case !input:
			bad("an argument outside the input struct")
		case hasShort || hasDef:
			bad("an argument takes no short and no default")
		case f.repeat:
			bad("an argument cannot repeat")
		case arg == "" || strings.ContainsFunc(arg, func(r rune) bool { return r <= ' ' || r == 0x7f || strings.ContainsRune("<>[]", r) }):
			bad("argument name %q cannot be shown", arg)
		case strings.ContainsAny(f.help, "\n\r"):
			bad("help text holds a line break")
		case slices.ContainsFunc(args, func(a *field) bool { return a.name == arg }):
			bad("argument %q declared twice", arg)
		case !f.opt && len(args) > 0 && args[len(args)-1].opt:
			bad("a needed argument after an optional one")
		}
		args = append(args, f)
	}
	return flags, args
}

// parseTag reads a struct tag in the conventional form, every key of it:
// reflect.StructTag can look a key up but cannot list them.
func parseTag(tag reflect.StructTag) (map[string]string, error) {
	out := map[string]string{}
	for s := strings.TrimLeft(string(tag), " "); s != ""; s = strings.TrimLeft(s, " ") {
		key, rest, ok := strings.Cut(s, ":")
		if !ok || key == "" || strings.ContainsAny(key, " \"") || !strings.HasPrefix(rest, `"`) {
			return nil, fmt.Errorf("tag `%s` is not in the form key:\"value\"", tag)
		}
		end := 1
		for end < len(rest) && rest[end] != '"' {
			if rest[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(rest) {
			return nil, fmt.Errorf("tag `%s` is not in the form key:\"value\"", tag)
		}
		val, err := strconv.Unquote(rest[:end+1])
		if err != nil {
			return nil, fmt.Errorf("tag `%s`: %v", tag, err)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("tag %q given twice", key)
		}
		out[key], s = val, rest[end+1:]
	}
	return out, nil
}

var textType = reflect.TypeFor[encoding.TextUnmarshaler]()

// typ finds how a field of type t is read.
func (b *builder) typ(f *field, t reflect.Type) error {
	f.one = t
	if o, ok := reflect.New(t).Interface().(optional); ok {
		f.opt, f.one = true, o.one()
	} else if r, ok := reflect.Zero(t).Interface().(repeated); ok {
		f.repeat, f.one = true, r.one()
	}
	f.elem = f.one
	if wrapper(f.one) {
		return fmt.Errorf("%s: Opt and Repeat do not nest", t)
	}
	if b.reader(f) {
		return nil
	}
	if f.one.Kind() == reflect.Slice {
		f.list, f.elem = true, f.one.Elem()
		if b.reader(f) {
			return nil
		}
	}
	return fmt.Errorf("%s cannot be read: give it an UnmarshalText method, or New a Reader", f.elem)
}

func wrapper(t reflect.Type) bool {
	_, opt := reflect.New(t).Interface().(optional)
	_, rep := reflect.Zero(t).Interface().(repeated)
	return opt || rep
}

// reader sets how f.elem is read: a LateReader, a Reader, the type's own
// method, or the library for Go's own basic types. A named type must say
// how it is read: time.Duration read as a bare number would be a trap.
func (b *builder) reader(f *field) bool {
	t := f.elem
	switch {
	case wrapper(t):
		return false
	case b.late[t] != nil:
		f.late = b.late[t]
	case b.readers[t] != nil:
		f.read = b.readers[t]
	case reflect.PointerTo(t).Implements(textType):
		f.read = func(s string) (reflect.Value, error) {
			v := reflect.New(t)
			err := v.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(s))
			return v.Elem(), err
		}
	case t.PkgPath() != "":
		return false
	default:
		f.read = basic(t)
	}
	return f.read != nil || f.late != nil
}

// basic reads Go's own basic types. Numbers are decimal.
func basic(t reflect.Type) readFn {
	set := func(put func(reflect.Value)) (reflect.Value, error) {
		v := reflect.New(t).Elem()
		put(v)
		return v, nil
	}
	switch t.Kind() {
	case reflect.String:
		return func(s string) (reflect.Value, error) { return reflect.ValueOf(s), nil }
	case reflect.Bool:
		return func(s string) (reflect.Value, error) {
			if s != "true" && s != "false" {
				return reflect.Value{}, ErrBool
			}
			return reflect.ValueOf(s == "true"), nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return func(s string) (reflect.Value, error) {
			n, err := strconv.ParseInt(s, 10, t.Bits())
			if err != nil {
				return reflect.Value{}, err
			}
			return set(func(v reflect.Value) { v.SetInt(n) })
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return func(s string) (reflect.Value, error) {
			n, err := strconv.ParseUint(s, 10, t.Bits())
			if err != nil {
				return reflect.Value{}, err
			}
			return set(func(v reflect.Value) { v.SetUint(n) })
		}
	case reflect.Float32, reflect.Float64:
		return func(s string) (reflect.Value, error) {
			n, err := strconv.ParseFloat(s, t.Bits())
			if err != nil {
				return reflect.Value{}, err
			}
			return set(func(v reflect.Value) { v.SetFloat(n) })
		}
	}
	return nil
}

// split cuts one occurrence into the words its elements are read from.
func (f *field) split(text string) ([]string, error) {
	if !f.list {
		return []string{text}, nil
	}
	if text == "" {
		return nil, ErrEmpty
	}
	items := strings.Split(text, ",")
	if slices.Contains(items, "") {
		return nil, ErrEmptyItem
	}
	return items, nil
}

// parse reads one occurrence of a field that is not late.
func (f *field) parse(text string) ([]reflect.Value, error) {
	items, err := f.split(text)
	if err != nil {
		return nil, err
	}
	vals := make([]reflect.Value, len(items))
	for i, it := range items {
		if vals[i], err = f.read(it); err != nil {
			return nil, err
		}
	}
	return vals, nil
}

// store puts one occurrence into the field dst.
func (f *field) store(dst reflect.Value, vals []reflect.Value) {
	v := vals[0]
	if f.list {
		v = reflect.Append(reflect.MakeSlice(f.one, 0, len(vals)), vals...)
	}
	switch {
	case f.opt:
		dst.Addr().Interface().(optional).set(v)
	case f.repeat:
		dst.Set(reflect.Append(dst, v))
	default:
		dst.Set(v)
	}
}
