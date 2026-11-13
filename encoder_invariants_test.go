// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.29 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// The tests in this file lock the evaluation order and the limit checks of
// the encoder. They exist so that a refactor of the encoder cannot change
// the output, the truncation records or the number of timer checks without
// a test failure.

// countdownTimer returns false from Exhausted() `left` times, then true. It
// counts every call to Exhausted().
type countdownTimer struct {
	left  int
	calls int
}

func (c *countdownTimer) Exhausted() bool {
	c.calls++
	if c.left > 0 {
		c.left--
		return false
	}
	return true
}

func (*countdownTimer) Start() time.Time                      { return time.Time{} }
func (*countdownTimer) Stop() time.Duration                   { return 0 }
func (*countdownTimer) Spent() time.Duration                  { return 0 }
func (*countdownTimer) Remaining() time.Duration              { return 0 }
func (*countdownTimer) Timed(func(timer.Timer)) time.Duration { return 0 }

// switchTimer reports the value of its flag.
type switchTimer struct {
	exhausted bool
}

func (s *switchTimer) Exhausted() bool                     { return s.exhausted }
func (*switchTimer) Start() time.Time                      { return time.Time{} }
func (*switchTimer) Stop() time.Duration                   { return 0 }
func (*switchTimer) Spent() time.Duration                  { return 0 }
func (*switchTimer) Remaining() time.Duration              { return 0 }
func (*switchTimer) Timed(func(timer.Timer)) time.Duration { return 0 }

// spyEncodable counts the calls to its Encode method.
type spyEncodable struct {
	calls *int
}

func (s *spyEncodable) Encode(enc *Encoder, obj *WAFObject, _ int) error {
	*s.calls++
	enc.WriteString(obj, "spy")
	return nil
}

// hookEncodable can record a depth truncation and exhaust the timer while it
// is encoded. All its fields are unexported, so the reflect path sees a struct
// with no usable field.
type hookEncodable struct {
	timer   *switchTimer
	record  bool
	exhaust bool
}

func (h *hookEncodable) Encode(enc *Encoder, obj *WAFObject, _ int) error {
	if h.record {
		enc.Truncations.Record(ObjectTooDeep, -1)
	}
	if h.exhaust {
		h.timer.exhausted = true
	}
	enc.WriteString(obj, "x")
	return nil
}

type (
	namedAnySlice    []any
	namedAnyMap      map[string]any
	namedBytes       []byte
	namedStringSlice []string
)

// encodeResult is what the tests compare: the encoded object, the error, the
// recorded truncations and a call count (timer checks or Encodable calls).
type encodeResult struct {
	Object normalizedObject
	Err    error
	Trunc  map[TruncationReason][]int
	Calls  int
}

// encodeScenario is one input with the timer it runs against.
type encodeScenario struct {
	tmr   timer.Timer
	input any
	calls func() int
}

func (s encodeScenario) callCount() int {
	if s.calls == nil {
		return 0
	}
	return s.calls()
}

func scenarioSwitch(exhausted bool, input func(tm *switchTimer) any) func() encodeScenario {
	return func() encodeScenario {
		tm := &switchTimer{exhausted: exhausted}
		return encodeScenario{tmr: tm, input: input(tm)}
	}
}

func scenarioCountdown(left int, input any) func() encodeScenario {
	return func() encodeScenario {
		ct := &countdownTimer{left: left}
		return encodeScenario{tmr: ct, input: input, calls: func() int { return ct.calls }}
	}
}

func scenarioSpy(exhausted bool, wrap func(spy *spyEncodable) any) func() encodeScenario {
	return func() encodeScenario {
		n := 0
		return encodeScenario{
			tmr:   &switchTimer{exhausted: exhausted},
			input: wrap(&spyEncodable{calls: &n}),
			calls: func() int { return n },
		}
	}
}

func newInvariantEncoder(t *testing.T, pinner *runtime.Pinner, tmr timer.Timer, limits func(*EncoderConfig)) *encoder {
	t.Helper()

	cfg := EncoderConfig{
		Pinner:           pinner,
		Timer:            tmr,
		MaxObjectDepth:   10,
		MaxStringSize:    4096,
		MaxContainerSize: 100,
	}
	if limits != nil {
		limits(&cfg)
	}
	enc, err := newEncoder(cfg)
	require.NoError(t, err)
	return enc
}

func withDepth(depth uint16) func(*EncoderConfig) {
	return func(cfg *EncoderConfig) { cfg.MaxObjectDepth = depth }
}

func withContainerSize(size uint16) func(*EncoderConfig) {
	return func(cfg *EncoderConfig) { cfg.MaxContainerSize = size }
}

func withStringSize(size uint16) func(*EncoderConfig) {
	return func(cfg *EncoderConfig) { cfg.MaxStringSize = size }
}

// runEncode runs the public Encode method on the scenario.
func runEncode(t *testing.T, limits func(*EncoderConfig), s encodeScenario) encodeResult {
	t.Helper()

	var pinner runtime.Pinner
	defer pinner.Unpin()

	enc := newInvariantEncoder(t, &pinner, s.tmr, limits)
	obj, err := enc.Encode(s.input)
	return encodeResult{
		Object: normalizedObjectSnapshot(obj),
		Err:    err,
		Trunc:  enc.enc.Truncations.AsMap(),
		Calls:  s.callCount(),
	}
}

// Expected objects.

func objStr(s string) normalizedObject { return normalizedObject{Type: WAFStringType, String: s} }
func objInt(i int64) normalizedObject  { return normalizedObject{Type: WAFIntType, Int: i} }
func objUint(u uint64) normalizedObject {
	return normalizedObject{Type: WAFUintType, Uint: u}
}
func objFloat(f float64) normalizedObject { return normalizedObject{Type: WAFFloatType, Float: f} }
func objNil() normalizedObject            { return normalizedObject{Type: WAFNilType} }

// objSkipped is the zero object: the encoder left it untouched.
func objSkipped() normalizedObject { return normalizedObject{Type: WAFInvalidType, Invalid: true} }

func objArray(items ...normalizedObject) normalizedObject {
	array := make([]normalizedObject, len(items))
	copy(array, items)
	return normalizedObject{Type: WAFArrayType, Array: array}
}

func objMap(entries ...normalizedMapEntry) normalizedObject {
	m := make([]normalizedMapEntry, len(entries))
	copy(m, entries)
	return normalizedObject{Type: WAFMapType, Map: m}
}

func entry(key string, value normalizedObject) normalizedMapEntry {
	return normalizedMapEntry{Key: key, Value: value}
}

func tooDeep(values ...int) map[TruncationReason][]int {
	return map[TruncationReason][]int{ObjectTooDeep: values}
}

func TestEncodeEvaluationOrder(t *testing.T) {
	t.Run("encodable hook", func(t *testing.T) {
		cases := []struct {
			name     string
			limits   func(*EncoderConfig)
			scenario func() encodeScenario
			want     encodeResult
		}{
			{
				name:     "E1 timeout runs before the hook",
				scenario: scenarioSpy(true, func(spy *spyEncodable) any { return spy }),
				want:     encodeResult{Object: objSkipped(), Err: waferrors.ErrTimeout},
			},
			{
				name:     "E2a pointer to pointer is not Encodable",
				scenario: scenarioSpy(false, func(spy *spyEncodable) any { return &spy }),
				want:     encodeResult{Object: objMap()},
			},
			{
				name:     "E2b hook runs before the depth check",
				limits:   withDepth(0),
				scenario: scenarioSpy(false, func(spy *spyEncodable) any { return spy }),
				want:     encodeResult{Object: objStr("spy"), Calls: 1},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.want, runEncode(t, tc.limits, tc.scenario()))
			})
		}
	})

	t.Run("reflect path", func(t *testing.T) {
		var selfPointer any
		selfPointer = &selfPointer

		type pair struct{ A int }

		cases := []struct {
			name        string
			value       reflect.Value
			depth       int
			measureOnly bool
			want        encodeResult
		}{
			{name: "E3 pointer limit, no object", value: reflect.ValueOf(selfPointer), depth: 10, measureOnly: true, want: encodeResult{Err: waferrors.ErrTooManyIndirections}},
			{name: "E3 pointer limit, with object", value: reflect.ValueOf(selfPointer), depth: 10, want: encodeResult{Object: objSkipped(), Err: waferrors.ErrTooManyIndirections}},
			{name: "E4 string, no object", value: reflect.ValueOf("abc"), depth: 10, measureOnly: true},
			{name: "E4 invalid, no object", value: reflect.Value{}, depth: 10, measureOnly: true},
			{name: "E4 depth 0, no object", value: reflect.ValueOf(42), measureOnly: true},
			{name: "E5 invalid value", value: reflect.Value{}, depth: 10, want: encodeResult{Object: objSkipped(), Err: waferrors.ErrUnsupportedValue}},
			{name: "E6 nil pointer", value: reflect.ValueOf((*pair)(nil)), depth: 10, want: encodeResult{Object: objNil()}},
			{name: "E6 nil map, depth 0", value: reflect.ValueOf(map[string]int(nil)), want: encodeResult{Object: objNil()}},
			{name: "E7 byte slice, depth 0", value: reflect.ValueOf([]byte("x")), want: encodeResult{Object: objSkipped()}},
			{name: "E7 byte array, depth 0", value: reflect.ValueOf([4]byte{1}), want: encodeResult{Object: objSkipped()}},
			{name: "E7 named byte slice, depth 0", value: reflect.ValueOf(namedBytes("x")), want: encodeResult{Object: objSkipped()}},
			{name: "E8 int8, depth 0", value: reflect.ValueOf(int8(3)), want: encodeResult{Object: objInt(3)}},
			{name: "E8 string, depth 0", value: reflect.ValueOf("s"), want: encodeResult{Object: objStr("s")}},
			{name: "E8 json.Number, depth 0", value: reflect.ValueOf(json.Number("12")), want: encodeResult{Object: objInt(12)}},
			{name: "E8 uintptr, depth 0", value: reflect.ValueOf(uintptr(7)), want: encodeResult{Object: objUint(7)}},
			{name: "E8 float32, depth 0", value: reflect.ValueOf(float32(0.1)), want: encodeResult{Object: objFloat(float64(float32(0.1)))}},
			{name: "E9 slice, depth 0", value: reflect.ValueOf([]int{1}), want: encodeResult{Object: objSkipped(), Err: waferrors.ErrMaxDepthExceeded, Trunc: tooDeep(-1)}},
			{name: "E9 map, depth 0", value: reflect.ValueOf(map[string]int{"a": 1}), want: encodeResult{Object: objSkipped(), Err: waferrors.ErrMaxDepthExceeded, Trunc: tooDeep(-1)}},
			{name: "E9 struct, depth 0", value: reflect.ValueOf(pair{1}), want: encodeResult{Object: objSkipped(), Err: waferrors.ErrMaxDepthExceeded, Trunc: tooDeep(-1)}},
			{name: "E10 chan, depth 0", value: reflect.ValueOf(make(chan int)), want: encodeResult{Object: objSkipped(), Err: waferrors.ErrMaxDepthExceeded, Trunc: tooDeep(-1)}},
			{name: "E10 complex, depth 0", value: reflect.ValueOf(complex(1, 2)), want: encodeResult{Object: objSkipped(), Err: waferrors.ErrMaxDepthExceeded, Trunc: tooDeep(-1)}},
			{name: "E10 func, depth 0", value: reflect.ValueOf(func() {}), want: encodeResult{Object: objSkipped(), Err: waferrors.ErrMaxDepthExceeded, Trunc: tooDeep(-1)}},
			{name: "E10 chan, depth 1", value: reflect.ValueOf(make(chan int)), depth: 1, want: encodeResult{Object: objSkipped(), Err: waferrors.ErrUnsupportedValue}},
			{name: "E10 complex, depth 1", value: reflect.ValueOf(complex(1, 2)), depth: 1, want: encodeResult{Object: objSkipped(), Err: waferrors.ErrUnsupportedValue}},
			{name: "E10 func, depth 1", value: reflect.ValueOf(func() {}), depth: 1, want: encodeResult{Object: objSkipped(), Err: waferrors.ErrUnsupportedValue}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.want, runReflectEncode(t, tc.value, tc.depth, tc.measureOnly))
			})
		}
	})
}

// runReflectEncode calls the reflect-based encode method directly. When
// measureOnly is true, it passes a nil object.
func runReflectEncode(t *testing.T, value reflect.Value, depth int, measureOnly bool) encodeResult {
	t.Helper()

	var pinner runtime.Pinner
	defer pinner.Unpin()

	enc := newInvariantEncoder(t, &pinner, &switchTimer{}, nil)
	var obj WAFObject
	target := &obj
	if measureOnly {
		target = nil
	}
	err := enc.encode(value, target, depth)
	return encodeResult{
		Object: normalizedObjectSnapshot(target),
		Err:    err,
		Trunc:  enc.enc.Truncations.AsMap(),
	}
}

func TestEncodeDepthRemeasure(t *testing.T) {
	// Each input records a depth truncation of -1 through the hook.
	recordingInputs := map[string]func(h *hookEncodable) any{
		"slice":  func(h *hookEncodable) any { return []any{h} },
		"map":    func(h *hookEncodable) any { return map[string]any{"k": h} },
		"direct": func(h *hookEncodable) any { return h },
		"struct": func(h *hookEncodable) any { return struct{ K *hookEncodable }{h} },
	}

	t.Run("R1 three records become one", func(t *testing.T) {
		input := []any{[]any{1}, []any{2}, []any{3}}
		scenario := scenarioSwitch(false, func(*switchTimer) any { return input })
		want := encodeResult{Object: objArray(), Trunc: tooDeep(2)}
		require.Equal(t, want, runEncode(t, withDepth(1), scenario()))
	})

	t.Run("R2 re-measure replaces the record", func(t *testing.T) {
		want := map[string]int{"slice": 2, "map": 2, "direct": 1, "struct": 2}
		for name, build := range recordingInputs {
			scenario := scenarioSwitch(false, func(tm *switchTimer) any {
				return build(&hookEncodable{timer: tm, record: true})
			})
			got := runEncode(t, nil, scenario())
			require.Equal(t, tooDeep(want[name]), got.Trunc, name)
		}
	})

	t.Run("R3 no re-measure when the timer is exhausted", func(t *testing.T) {
		for name, build := range recordingInputs {
			scenario := scenarioSwitch(false, func(tm *switchTimer) any {
				return build(&hookEncodable{timer: tm, record: true, exhaust: true})
			})
			got := runEncode(t, nil, scenario())
			require.Equal(t, tooDeep(-1), got.Trunc, name)
		}
	})

	t.Run("R4 the scalar path does not re-measure", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		tm := &switchTimer{}
		enc := newInvariantEncoder(t, &pinner, tm, nil)
		inputs := []any{
			[]any{&hookEncodable{timer: tm, record: true}},
			"x",
			struct{}{},
		}
		var got [][]int
		for _, input := range inputs {
			_, err := enc.Encode(input)
			require.NoError(t, err)
			got = append(got, append([]int(nil), enc.enc.Truncations.ObjectTooDeep...))
		}
		require.Equal(t, [][]int{{2}, {2}, {1}}, got)
	})
}

func TestEncodeTimeoutInContainers(t *testing.T) {
	hookExhaust := func(tm *switchTimer) *hookEncodable { return &hookEncodable{timer: tm, exhaust: true} }

	cases := []struct {
		name     string
		limits   func(*EncoderConfig)
		scenario func() encodeScenario
		want     encodeResult
	}{
		{
			name:     "T1 struct, timer exhausted",
			limits:   withDepth(0),
			scenario: scenarioSwitch(true, func(*switchTimer) any { return struct{}{} }),
			want:     encodeResult{Object: objSkipped(), Err: waferrors.ErrTimeout},
		},
		{
			name:     "T2 typed slice, timer exhausted",
			limits:   withDepth(0),
			scenario: scenarioSwitch(true, func(*switchTimer) any { return []string{"a"} }),
			want:     encodeResult{Object: objSkipped(), Err: waferrors.ErrTimeout},
		},
		{
			name: "T3 typed any slice, hook exhausts the timer",
			scenario: scenarioSwitch(false, func(tm *switchTimer) any {
				return []any{"a", hookExhaust(tm), "b"}
			}),
			want: encodeResult{Object: objArray(objStr("a"), objStr("x"))},
		},
		{
			name:     "T4 typed string slice, 3 timer checks",
			scenario: scenarioCountdown(2, []string{"a", "b", "c"}),
			want:     encodeResult{Object: objArray(objStr("a")), Calls: 3},
		},
		{
			name:     "T5 typed any slice, 4 timer checks",
			scenario: scenarioCountdown(2, []any{"v", "w"}),
			want:     encodeResult{Object: objArray(), Calls: 4},
		},
		{
			name:     "T6 typed any map, 3 timer checks",
			scenario: scenarioCountdown(2, map[string]any{"k": "v"}),
			want:     encodeResult{Object: objMap(entry("k", objSkipped())), Calls: 3},
		},
		{
			name:     "T7 named map, 3 timer checks",
			scenario: scenarioCountdown(2, namedAnyMap{"k": "v"}),
			want:     encodeResult{Object: objMap(entry("k", objSkipped())), Calls: 3},
		},
		{
			name:   "T8 named slice, timeout does not set the capacity flag",
			limits: withContainerSize(2),
			scenario: scenarioSwitch(false, func(tm *switchTimer) any {
				return namedAnySlice{"a", hookExhaust(tm), "b"}
			}),
			want: encodeResult{Object: objArray(objStr("a"), objStr("x"))},
		},
		{
			name:     "T9 named slice over capacity",
			limits:   withContainerSize(1),
			scenario: scenarioSwitch(false, func(*switchTimer) any { return namedAnySlice{"a", "b", "c"} }),
			want: encodeResult{
				Object: objArray(objStr("a")),
				Trunc:  map[TruncationReason][]int{ContainerTooLarge: {3}},
			},
		},
		{
			name: "T10 struct, hook exhausts the timer",
			scenario: scenarioSwitch(false, func(tm *switchTimer) any {
				return struct {
					A string
					B *hookEncodable
					C string
				}{"a", hookExhaust(tm), "c"}
			}),
			want: encodeResult{Object: objMap(entry("A", objStr("a")), entry("B", objStr("x")))},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, runEncode(t, tc.limits, tc.scenario()))
		})
	}
}

func TestEncodeScalarFastPathStringLimit(t *testing.T) {
	cases := []struct {
		name  string
		input any
		want  encodeResult
	}{
		{
			name:  "S1 string",
			input: "hello world",
			want:  encodeResult{Object: objStr("hell"), Trunc: map[TruncationReason][]int{StringTooLong: {11}}},
		},
		{
			name:  "S2 json.Number that is not a number",
			input: json.Number("bogus-number"),
			want:  encodeResult{Object: objStr("bogu"), Trunc: map[TruncationReason][]int{StringTooLong: {12}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scenario := scenarioSwitch(false, func(*switchTimer) any { return tc.input })
			require.Equal(t, tc.want, runEncode(t, withStringSize(4), scenario()))
		})
	}
}

// depthResult is what depthOf returns, with the number of timer checks.
type depthResult struct {
	Depth int
	Err   error
	Calls int
}

func runDepthOf(s encodeScenario) depthResult {
	depth, err := depthOf(s.tmr, reflect.ValueOf(s.input))
	return depthResult{Depth: depth, Err: err, Calls: s.callCount()}
}

func TestDepthOfBranches(t *testing.T) {
	var selfPointer any
	selfPointer = &selfPointer

	valueOf := func(input any) func() encodeScenario {
		return scenarioSwitch(false, func(*switchTimer) any { return input })
	}

	cases := []struct {
		name     string
		scenario func() encodeScenario
		want     depthResult
	}{
		{"D1 scalar", valueOf(42), depthResult{}},
		{"D2 byte slice", valueOf([]byte("x")), depthResult{}},
		{"D2 byte array", valueOf([4]byte{}), depthResult{Depth: 1}},
		{"D2 named byte slice", valueOf(namedBytes("x")), depthResult{Depth: 1}},
		{"D3 nested slices", valueOf([]any{[]any{1}, []any{[]any{2}}}), depthResult{Depth: 3}},
		{"D4 nested maps", valueOf(map[string]any{"a": map[string]any{"b": 1}}), depthResult{Depth: 2}},
		{"D4 empty map", valueOf(map[string]any{}), depthResult{Depth: 1}},
		{"D4 empty slice", valueOf([]any{}), depthResult{Depth: 1}},
		{
			"D5 unexported field is skipped",
			valueOf(struct{ a, B []any }{a: []any{[]any{[]any{1}}}, B: []any{1}}),
			depthResult{Depth: 2},
		},
		{
			"D5 json:- field is skipped",
			valueOf(struct {
				A []any `json:"-"`
				B int
			}{A: []any{[]any{1}}}),
			depthResult{Depth: 1},
		},
		{
			"D5 ddwaf:ignore field is counted",
			valueOf(struct {
				A []any `ddwaf:"ignore"`
			}{A: []any{[]any{1}}}),
			depthResult{Depth: 3},
		},
		{"D6 pointer to slice", valueOf(&[]any{1}), depthResult{Depth: 1}},
		{"D6 self pointer", valueOf(selfPointer), depthResult{}},
		{"D7 timer exhausted", scenarioSwitch(true, func(*switchTimer) any { return []any{1} }), depthResult{Err: waferrors.ErrTimeout}},
		{
			"D8 array loop stops at the first error",
			scenarioCountdown(3, []any{[]any{1}, "x", []any{[]any{2}}}),
			depthResult{Depth: 2, Err: waferrors.ErrTimeout, Calls: 4},
		},
		{
			"D9 map loop keeps the depth of the failing child",
			scenarioCountdown(2, map[string]any{"k": []any{1}}),
			depthResult{Depth: 2, Err: waferrors.ErrTimeout, Calls: 3},
		},
		{
			"D10 struct loop keeps the depth of the failing child",
			scenarioCountdown(2, struct{ A, B []any }{A: []any{1}, B: []any{[]any{2}}}),
			depthResult{Depth: 2, Err: waferrors.ErrTimeout, Calls: 3},
		},
		{
			"D11 array loop keeps the depth of the failing child",
			scenarioCountdown(2, []any{[]any{1}}),
			depthResult{Depth: 2, Err: waferrors.ErrTimeout, Calls: 3},
		},
		{
			"D12 map loop stops at the first error",
			scenarioCountdown(2, map[string]any{"a": []any{1}, "b": []any{1}}),
			depthResult{Depth: 2, Err: waferrors.ErrTimeout, Calls: 3},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, runDepthOf(tc.scenario()))
		})
	}
}

// benchStruct is the reflect-path fixture of BenchmarkEncoderPaths.
type benchStruct struct {
	Name    string
	Count   int64
	Tags    []string
	Labels  map[string]string
	Ratio   *float64
	Enabled bool
}

type encoderPathCase struct {
	name string
	long bool // use the limits of BenchmarkEncoder
	data any
}

func benchStructs() []benchStruct {
	ratio := 0.5
	items := make([]benchStruct, 20)
	for i := range items {
		items[i] = benchStruct{
			Name:    fmt.Sprintf("item-%02d-with-a-longer-name", i),
			Count:   int64(i),
			Tags:    []string{"alpha-tag-value", "beta-tag-value", "gamma-tag-value"},
			Labels:  map[string]string{"label-key": "label-value-that-is-long"},
			Ratio:   &ratio,
			Enabled: i%2 == 0,
		}
	}
	return items
}

func benchStrings() namedStringSlice {
	items := make(namedStringSlice, 100)
	for i := range items {
		items[i] = fmt.Sprintf("%028d", i)
	}
	return items
}

func benchDeepSlice() any {
	var data any = "leaf"
	for range 30 {
		data = []any{data}
	}
	return data
}

// benchLongStrings is the fixture of BenchmarkEncoder for a string length.
func benchLongStrings(full string, length int) map[string]any {
	str := full[:length]
	slice := []string{str, str, str, str, str, str, str, str, str, str}
	data := make(map[string]any, 10)
	for i := range 10 {
		data[fmt.Sprintf("k%d", i)] = slice
	}
	return data
}

func encoderPathCases() []encoderPathCase {
	buf := make([]byte, 16384)
	if n, err := rand.New(rand.NewSource(33)).Read(buf); err != nil || n != len(buf) {
		panic("cannot build the benchmark fixture")
	}
	full := string(buf)

	cases := []encoderPathCase{
		{name: "scalar/int64", data: int64(42)},
		{name: "scalar/float64", data: 3.5},
		{name: "scalar/string", data: "hello"},
		{name: "reflect/strings", data: benchStrings()},
		{name: "reflect/structs", data: benchStructs()},
		{name: "typed/request", data: benchBenignRequest()},
		{name: "remeasure/deep", data: benchDeepSlice()},
	}
	for _, length := range []int{1024, 4096, 8192, 16384} {
		cases = append(cases, encoderPathCase{
			name: fmt.Sprintf("long-strings/%d", length),
			long: true,
			data: benchLongStrings(full, length),
		})
	}
	return cases
}

// BenchmarkEncoderPaths measures the encoder on the paths that the complexity
// refactor changes. Each iteration builds a new encoder and releases its pins.
func BenchmarkEncoderPaths(b *testing.B) {
	tmr, err := timer.NewTimer(timer.WithUnlimitedBudget())
	require.NoError(b, err)

	var pinner runtime.Pinner
	defer pinner.Unpin()

	defaults := newEncoderConfig(&pinner, WithTimer(tmr))
	longCfg := EncoderConfig{
		Pinner:           &pinner,
		Timer:            tmr,
		MaxObjectDepth:   10,
		MaxStringSize:    math.MaxUint16,
		MaxContainerSize: 100,
	}

	for _, tc := range encoderPathCases() {
		cfg := defaults
		if tc.long {
			cfg = longCfg
		}
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				enc, err := newEncoder(cfg)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := enc.Encode(tc.data); err != nil {
					b.Fatal(err)
				}
				pinner.Unpin()
			}
		})
	}
}
