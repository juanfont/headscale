package own

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Errors carry what the layer needs to write its own sentence (D4).
type (
	UnknownCommandError struct {
		Path []string
		Word string
	}
	UnknownFlagError struct {
		Path []string
		Flag string // as typed: "--force", "-r"
	}
	MissingValueError struct {
		Path []string
		Flag string
	}
	BadValueError struct {
		Path        []string
		Flag, Value string
	}
)

func (e *UnknownCommandError) Error() string {
	return "unknown command " + strconv.Quote(e.Word) + " for " + strconv.Quote(pathString(e.Path))
}
func (e *UnknownFlagError) Error() string  { return "unknown flag: " + e.Flag }
func (e *MissingValueError) Error() string { return "flag needs a value: " + e.Flag }
func (e *BadValueError) Error() string {
	return "invalid value " + strconv.Quote(e.Value) + " for " + e.Flag
}

// Parser reads flags out of argv. With stop set it returns at the first
// positional or "--" (left in rest) so the dispatcher can read a command word.
// Values maps a long name to every value given, in order.
type Parser func(flags []Flag, argv []string, stop bool) (vals map[string][]string, rest []string, err error)

// OwnParse is variant 2: the grammar of requirements.md section 2, plus
// -o=json and --bool=false (D9, D11). -ojson is refused.
func OwnParse(flags []Flag, argv []string, stop bool) (map[string][]string, []string, error) {
	vals := map[string][]string{}
	var args []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			if stop {
				return vals, argv[i:], nil
			}
			return vals, append(args, argv[i+1:]...), nil
		}
		if len(a) < 2 || a[0] != '-' { // "", "-", words
			if stop {
				return vals, argv[i:], nil
			}
			args = append(args, a)
			continue
		}
		var name, val, typed string
		var hasVal bool
		short := a[1] != '-'
		if short {
			_, n := utf8.DecodeRuneInString(a[1:])
			name, typed = a[1:1+n], a[:1+n]
			if rest := a[1+n:]; rest != "" { // -o=json yes, -ojson no (D11)
				if rest[0] != '=' {
					return nil, nil, &UnknownFlagError{Flag: a}
				}
				val, hasVal = rest[1:], true
			}
		} else {
			name, val, hasVal = strings.Cut(a[2:], "=")
			typed = "--" + name
		}
		f := lookup(flags, name, short)
		if f == nil {
			return nil, nil, &UnknownFlagError{Flag: typed}
		}
		switch {
		case f.Kind == Bool && !hasVal:
			val = "true"
		case f.Kind == Bool:
			b, err := strconv.ParseBool(val)
			if err != nil || short { // no grouped shorts: -hx
				return nil, nil, &BadValueError{Flag: typed, Value: val}
			}
			val = strconv.FormatBool(b)
		case !hasVal:
			if i+1 == len(argv) {
				return nil, nil, &MissingValueError{Flag: typed}
			}
			i++
			val = argv[i] // taken verbatim, even "-last-seen" or "--"
		}
		vals[f.Long] = append(vals[f.Long], val)
	}
	return vals, args, nil
}
