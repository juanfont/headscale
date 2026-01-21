package db

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"reflect"

	"gorm.io/gorm/schema"
)

// Sentinel errors for text serialisation.
var (
	ErrTextUnmarshalFailed = errors.New("failed to unmarshal text value")
	ErrUnsupportedType     = errors.New("unsupported type")
	ErrTextMarshalerOnly   = errors.New("only encoding.TextMarshaler is supported")
)

// Got from https://github.com/xdg-go/strum/blob/main/types.go
var textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()

func isTextUnmarshaler(rv reflect.Value) bool {
	return rv.Type().Implements(textUnmarshalerType)
}

func maybeInstantiatePtr(rv reflect.Value) {
	if rv.Kind() == reflect.Pointer && rv.IsNil() {
		np := reflect.New(rv.Type().Elem())
		rv.Set(np)
	}
}

func decodingError(name string, err error) error {
	return fmt.Errorf("error decoding to %s: %w", name, err)
}

// TextSerialiser implements the Serialiser interface for fields that
// have a type that implements encoding.TextUnmarshaler.
type TextSerialiser struct{}

func (TextSerialiser) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue any) error {
	fieldValue := reflect.New(field.FieldType)

	// If the field is a pointer, we need to dereference it to get the actual type
	// so we do not end with a second pointer.
	if fieldValue.Elem().Kind() == reflect.Pointer {
		fieldValue = fieldValue.Elem()
	}

	if dbValue != nil {
		var bytes []byte

		switch v := dbValue.(type) {
		case []byte:
			bytes = v
		case string:
			bytes = []byte(v)
		default:
			return fmt.Errorf("%w: %#v", ErrTextUnmarshalFailed, dbValue)
		}

		if isTextUnmarshaler(fieldValue) {
			maybeInstantiatePtr(fieldValue)
			f := fieldValue.MethodByName("UnmarshalText")
			args := []reflect.Value{reflect.ValueOf(bytes)}

			ret := f.Call(args)
			if !ret[0].IsNil() {
				//nolint:forcetypeassert
				return decodingError(field.Name, ret[0].Interface().(error))
			}

			// If the underlying field is to a pointer type, we need to
			// assign the value as a pointer to it.
			// If it is not a pointer, we need to assign the value to the
			// field.
			dstField := field.ReflectValueOf(ctx, dst)
			if dstField.Kind() == reflect.Pointer {
				dstField.Set(fieldValue)
			} else {
				dstField.Set(fieldValue.Elem())
			}

			return nil
		} else {
			return fmt.Errorf("%w: %T", ErrUnsupportedType, fieldValue.Interface())
		}
	}

	return nil
}

func (TextSerialiser) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue any) (any, error) {
	switch v := fieldValue.(type) {
	case encoding.TextMarshaler:
		// If the value is nil, we return nil, however, go nil values are not
		// always comparable, particularly when reflection is involved:
		// https://dev.to/arxeiss/in-go-nil-is-not-equal-to-nil-sometimes-jn8
		if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
			return nil, nil //nolint:nilnil
		}

		b, err := v.MarshalText()
		if err != nil {
			return nil, err
		}

		return string(b), nil
	default:
		return nil, fmt.Errorf("%w, got %T", ErrTextMarshalerOnly, v)
	}
}
