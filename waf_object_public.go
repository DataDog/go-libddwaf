package libddwaf

import (
	"unsafe"

	wafBindings "github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/pin"
)

// WAFObject is a WAF object that can be passed to the WAF engine.
type WAFObject struct {
	inner *wafBindings.WAFObject
}

// WAFObjectKV is a key-value pair used in v2 maps.
type WAFObjectKV struct {
	inner *wafBindings.WAFObjectKV
}

func newWAFObject() WAFObject {
	return WAFObject{inner: new(wafBindings.WAFObject)}
}

func (w *WAFObject) raw() *wafBindings.WAFObject {
	return w.inner
}

func wrapWAFObject(raw *wafBindings.WAFObject) WAFObject {
	return WAFObject{inner: raw}
}

func wrapWAFObjectPtr(raw *wafBindings.WAFObject) *WAFObject {
	if raw == nil {
		return nil
	}
	return &WAFObject{inner: raw}
}

func wrapWAFObjects(items []wafBindings.WAFObject) []WAFObject {
	if len(items) == 0 {
		return nil
	}
	wrapped := make([]WAFObject, len(items))
	for i := range items {
		wrapped[i] = wrapWAFObject(&items[i])
	}
	return wrapped
}

//go:nosplit
//go:nocheckptr
func unwrapWAFObjects(items []WAFObject) []wafBindings.WAFObject {
	n := len(items)
	if n == 0 {
		return nil
	}
	first := items[0].inner
	if n == 1 {
		return unsafe.Slice(first, 1)
	}
	stride := unsafe.Sizeof(wafBindings.WAFObject{})
	if uintptr(unsafe.Pointer(items[n-1].inner)) == uintptr(unsafe.Pointer(first))+uintptr(n-1)*stride {
		return unsafe.Slice(first, n)
	}
	inner := make([]wafBindings.WAFObject, n)
	for i := range items {
		inner[i] = *items[i].inner
	}
	return inner
}

func newWAFObjectKV() WAFObjectKV {
	return WAFObjectKV{inner: new(wafBindings.WAFObjectKV)}
}

func (kv *WAFObjectKV) raw() *wafBindings.WAFObjectKV {
	return kv.inner
}

func wrapWAFObjectKV(raw *wafBindings.WAFObjectKV) WAFObjectKV {
	return WAFObjectKV{inner: raw}
}

func wrapWAFObjectKVs(entries []wafBindings.WAFObjectKV) []WAFObjectKV {
	if len(entries) == 0 {
		return nil
	}
	wrapped := make([]WAFObjectKV, len(entries))
	for i := range entries {
		wrapped[i] = wrapWAFObjectKV(&entries[i])
	}
	return wrapped
}

//go:nosplit
//go:nocheckptr
func unwrapWAFObjectKVs(entries []WAFObjectKV) []wafBindings.WAFObjectKV {
	n := len(entries)
	if n == 0 {
		return nil
	}
	first := entries[0].inner
	if n == 1 {
		return unsafe.Slice(first, 1)
	}
	stride := unsafe.Sizeof(wafBindings.WAFObjectKV{})
	if uintptr(unsafe.Pointer(entries[n-1].inner)) == uintptr(unsafe.Pointer(first))+uintptr(n-1)*stride {
		return unsafe.Slice(first, n)
	}
	inner := make([]wafBindings.WAFObjectKV, n)
	for i := range entries {
		inner[i] = *entries[i].inner
	}
	return inner
}

// Type returns the type of the WAF object.
func (w *WAFObject) Type() string {
	return w.raw().Type().String()
}

// IsInvalid returns true if the WAF object is invalid.
func (w *WAFObject) IsInvalid() bool { return w.raw().IsInvalid() }

// IsNil returns true if the WAF object is nil.
func (w *WAFObject) IsNil() bool { return w.raw().IsNil() }

// IsMap returns true if the WAF object is a map.
func (w *WAFObject) IsMap() bool { return w.raw().IsMap() }

// IsArray returns true if the WAF object is an array.
func (w *WAFObject) IsArray() bool { return w.raw().IsArray() }

// IsInt returns true if the WAF object is an int.
func (w *WAFObject) IsInt() bool { return w.raw().IsInt() }

// IsUint returns true if the WAF object is a uint.
func (w *WAFObject) IsUint() bool { return w.raw().IsUint() }

// IsBool returns true if the WAF object is a bool.
func (w *WAFObject) IsBool() bool { return w.raw().IsBool() }

// IsFloat returns true if the WAF object is a float.
func (w *WAFObject) IsFloat() bool { return w.raw().IsFloat() }

// IsString returns true if the WAF object is a string.
func (w *WAFObject) IsString() bool { return w.raw().IsString() }

// IsUnusable returns true if the WAF object is unusable.
func (w *WAFObject) IsUnusable() bool { return w.raw().IsUnusable() }

// SetNil sets the WAF object to nil.
func (w *WAFObject) SetNil() { w.raw().SetNil() }

// SetInvalid sets the WAF object to invalid.
func (w *WAFObject) SetInvalid() { w.raw().SetInvalid() }

// SetBool sets the WAF object to a bool.
func (w *WAFObject) SetBool(b bool) { w.raw().SetBool(b) }

// SetInt sets the WAF object to an int.
func (w *WAFObject) SetInt(i int64) { w.raw().SetInt(i) }

// SetUint sets the WAF object to a uint.
func (w *WAFObject) SetUint(i uint64) { w.raw().SetUint(i) }

// SetFloat sets the WAF object to a float.
func (w *WAFObject) SetFloat(f float64) { w.raw().SetFloat(f) }

// SetString sets the WAF object to a string.
func (w *WAFObject) SetString(pinner pin.Pinner, str string) { w.raw().SetString(pinner, str) }

// SetLiteralString sets the WAF object to a literal string.
func (w *WAFObject) SetLiteralString(pinner pin.Pinner, str string) {
	w.raw().SetLiteralString(pinner, str)
}

// SetArray sets the WAF object to an array.
func (w *WAFObject) SetArray(pinner pin.Pinner, capacity uint16) []WAFObject {
	return wrapWAFObjects(w.raw().SetArray(pinner, capacity))
}

// SetArrayData sets the WAF object to an array with the provided items.
func (w *WAFObject) SetArrayData(pinner pin.Pinner, data []WAFObject) error {
	return w.raw().SetArrayData(pinner, unwrapWAFObjects(data))
}

// SetArraySize sets the array size.
func (w *WAFObject) SetArraySize(size uint16) { w.raw().SetArraySize(size) }

// SetMap sets the WAF object to a map.
func (w *WAFObject) SetMap(pinner pin.Pinner, capacity uint16) []WAFObjectKV {
	return wrapWAFObjectKVs(w.raw().SetMap(pinner, capacity))
}

// SetMapData sets the WAF object to a map with the provided entries.
func (w *WAFObject) SetMapData(pinner pin.Pinner, data []WAFObjectKV) error {
	return w.raw().SetMapData(pinner, unwrapWAFObjectKVs(data))
}

// SetMapSize sets the map size.
func (w *WAFObject) SetMapSize(size uint16) { w.raw().SetMapSize(size) }

// BoolValue returns the bool value.
func (w *WAFObject) BoolValue() (bool, error) { return w.raw().BoolValue() }

// IntValue returns the int value.
func (w *WAFObject) IntValue() (int64, error) { return w.raw().IntValue() }

// UIntValue returns the uint value.
func (w *WAFObject) UIntValue() (uint64, error) { return w.raw().UIntValue() }

// FloatValue returns the float value.
func (w *WAFObject) FloatValue() (float64, error) { return w.raw().FloatValue() }

// StringValue returns the string value.
func (w *WAFObject) StringValue() (string, error) { return w.raw().StringValue() }

// ArraySize returns the array size.
func (w *WAFObject) ArraySize() (uint16, error) { return w.raw().ArraySize() }

// ArrayValues returns the array items.
func (w *WAFObject) ArrayValues() ([]WAFObject, error) {
	items, err := w.raw().ArrayValues()
	if err != nil {
		return nil, err
	}
	return wrapWAFObjects(items), nil
}

// MapSize returns the map size.
func (w *WAFObject) MapSize() (uint16, error) { return w.raw().MapSize() }

// MapEntries returns the map entries.
func (w *WAFObject) MapEntries() ([]WAFObjectKV, error) {
	entries, err := w.raw().MapEntries()
	if err != nil {
		return nil, err
	}
	return wrapWAFObjectKVs(entries), nil
}

// ArrayValue returns the array as a generic slice.
func (w *WAFObject) ArrayValue() ([]any, error) { return w.raw().ArrayValue() }

// MapValue returns the map as a generic map.
func (w *WAFObject) MapValue() (map[string]any, error) { return w.raw().MapValue() }

// AnyValue returns the value as a generic Go value.
func (w *WAFObject) AnyValue() (any, error) { return w.raw().AnyValue() }

// Key returns the key object.
func (kv *WAFObjectKV) Key() *WAFObject { return wrapWAFObjectPtr(&kv.raw().Key) }

// Value returns the value object.
func (kv *WAFObjectKV) Value() *WAFObject { return wrapWAFObjectPtr(&kv.raw().Val) }
