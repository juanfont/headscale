package types

import (
	"encoding"
	"reflect"
)

// ConfigField is one key of the configuration: a leaf value or an open map.
type ConfigField struct {
	// Path is the dotted key, e.g. "dns.nameservers.global".
	Path  string
	Field reflect.StructField
	// Value is the field in the walked Config; it is settable.
	Value reflect.Value
	// Open marks a map, whose keys the user chooses.
	Open bool
}

var textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()

// ConfigFields lists every leaf and open map of cfg reachable through koanf
// tags, in declaration order. A struct is a leaf when *T unmarshals text;
// otherwise it is descended into. Fields tagged koanf:"-" are skipped.
func ConfigFields(cfg *Config) []ConfigField {
	return appendConfigFields(nil, "", reflect.ValueOf(cfg).Elem())
}

func appendConfigFields(fields []ConfigField, prefix string, v reflect.Value) []ConfigField {
	for f, fv := range v.Fields() {
		name := f.Tag.Get("koanf")
		if !f.IsExported() || name == "" || name == "-" {
			continue
		}

		path := prefix + name

		if f.Type.Kind() == reflect.Struct && !reflect.PointerTo(f.Type).Implements(textUnmarshalerType) {
			fields = appendConfigFields(fields, path+".", fv)

			continue
		}

		fields = append(fields, ConfigField{
			Path:  path,
			Field: f,
			Value: fv,
			Open:  f.Type.Kind() == reflect.Map,
		})
	}

	return fields
}
