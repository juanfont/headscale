package apiv0

import (
	"reflect"

	"github.com/danielgtaylor/huma/v2"
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// Optional is a body field that may be left out. RFC 7396 reads a PATCH
// field three ways: left out (no change), null (clear), or a value; a Go
// pointer cannot tell the first two apart. Its schema is the schema of T;
// register refuses null for a field not tagged nullable:"true". Every field
// of a body that is not required is an Optional with omitzero, and every
// field of a PATCH body; register refuses any other.
type Optional[T any] struct {
	// Set is true when the field was in the body.
	Set bool
	// Null is true when it was null.
	Null  bool
	Value T
}

// UnmarshalJSONFrom runs only for a field that is in the body. It decodes T
// with the options of the whole body, so a struct in T is read as strictly.
func (o *Optional[T]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	// A field given twice must not keep parts of both.
	*o = Optional[T]{Set: true}

	if dec.PeekKind() == 'n' {
		o.Null = true
		_, err := dec.ReadToken()

		return err
	}

	return jsonv2.UnmarshalDecode(dec, &o.Value)
}

// Schema is T's: the client sees a plain optional field.
func (Optional[T]) Schema(r huma.Registry) *huma.Schema {
	return r.Schema(reflect.TypeFor[T](), true, "")
}

func (o Optional[T]) isSet() bool  { return o.Set }
func (o Optional[T]) isNull() bool { return o.Null }

// optionalField is what register looks for in a body.
type optionalField interface {
	isSet() bool
	isNull() bool
}

var optionalFieldType = reflect.TypeFor[optionalField]()
