package types

import (
	"encoding"
	"reflect"
	"slices"
)

// ConfigField is one key of the configuration: a section, a leaf value or
// an open map.
type ConfigField struct {
	// Path is the dotted key, e.g. "dns.nameservers.global".
	Path  string
	Field reflect.StructField
	// Value is the field in the walked Config; it is settable.
	Value reflect.Value
	// Open marks a map, whose keys the user chooses.
	Open bool
	// Section marks a struct whose fields are the keys below Path.
	Section bool
	// Doc is the field's doc comment, from config_docs_generated.go.
	Doc string
}

var textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()

// ConfigTree lists every section, leaf and open map of cfg reachable
// through koanf tags, in declaration order, each section before its keys.
// A struct is a leaf when *T unmarshals text; otherwise it is a section.
// Fields tagged koanf:"-" are skipped.
func ConfigTree(cfg *Config) []ConfigField {
	return appendConfigTree(nil, "", reflect.ValueOf(cfg).Elem())
}

// ConfigFields is [ConfigTree] without its sections.
func ConfigFields(cfg *Config) []ConfigField {
	return slices.DeleteFunc(ConfigTree(cfg), func(f ConfigField) bool { return f.Section })
}

// ConfigValueDoc is the doc comment of enum's constant holding value, or "".
func ConfigValueDoc(enum reflect.Type, value string) string {
	return configValueDocs[enum.Name()+"="+value]
}

func appendConfigTree(fields []ConfigField, prefix string, v reflect.Value) []ConfigField {
	for f, fv := range v.Fields() {
		name := f.Tag.Get("koanf")
		if !f.IsExported() || name == "" || name == "-" {
			continue
		}

		path := prefix + name
		section := f.Type.Kind() == reflect.Struct && !reflect.PointerTo(f.Type).Implements(textUnmarshalerType)

		fields = append(fields, ConfigField{
			Path:    path,
			Field:   f,
			Value:   fv,
			Open:    f.Type.Kind() == reflect.Map,
			Section: section,
			Doc:     configFieldDocs[v.Type().Name()+"."+f.Name],
		})

		if section {
			fields = appendConfigTree(fields, path+".", fv)
		}
	}

	return fields
}
