package kmip

import "reflect"

type AfterUnmarshalKMIP interface {
	AfterUnmarshalKMIP()
}

func runAfterUnmarshalHooks(v any) {
	runHooksRV(reflect.ValueOf(v))
}

func runHooksRV(rv reflect.Value) {
	if !rv.IsValid() {
		return
	}
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return
		}
		rv = rv.Elem()
	}
	if rv.CanAddr() {
		addr := rv.Addr()
		if addr.IsValid() && addr.CanInterface() {
			if h, ok := addr.Interface().(AfterUnmarshalKMIP); ok {
				h.AfterUnmarshalKMIP()
			}
		}
	}
	switch rv.Kind() {
	case reflect.Struct:
		for i := 0; i < rv.NumField(); i++ {
			runHooksRV(rv.Field(i))
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			runHooksRV(rv.Index(i))
		}
	case reflect.Map:
		for _, k := range rv.MapKeys() {
			runHooksRV(rv.MapIndex(k))
		}
	}
}
