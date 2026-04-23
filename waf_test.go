// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.27 && !datadog.no_waf && (cgo || appsec)

package libddwaf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/lib"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	if ok, err := Load(); !ok {
		panic(err)
	}
}

func TestLoad(t *testing.T) {
	ok, err := Load()
	require.True(t, ok)
	require.NoError(t, err)

	ok, err = Load()
	require.True(t, ok)
	require.NoError(t, err)
}

func TestUsable(t *testing.T) {
	supported, err := Usable()
	require.True(t, supported)
	require.NoError(t, err)
}

func TestVersion(t *testing.T) {
	// Ensures the library version matches the expected version...
	require.Equal(t, lib.EmbeddedWAFVersion, Version())
}

var testArachniRule = newArachniTestRule([]ruleInput{{Address: "server.request.headers.no_cookies", KeyPath: []string{"user-agent"}}}, nil)

var testArachniRuleTmpl = template.Must(template.New("").Parse(`
{
  "version": "2.1",
  "rules": [
	{
	  "id": "ua0-600-12x",
	  "name": "Arachni",
	  "tags": {
		"type": "security_scanner",
		"category": "attack_attempt"
	  },
	  "conditions": [
		{
		  "operator": "match_regex",
		  "parameters": {
			"inputs": [
			{{ range $i, $input := .Inputs -}}
			  {{ if gt $i 0 }},{{ end }}
				{ "address": "{{ $input.Address }}"{{ if ne (len $input.KeyPath) 0 }},  "key_path": [ {{ range $i, $path := $input.KeyPath }}{{ if gt $i 0 }}, {{ end }}"{{ $path }}"{{ end }} ]{{ end }} }
			{{- end }}
			],
			"regex": "^Arachni"
		  }
		}
	  ],
	  "transformers": []
	  {{- if .Actions }},
		"on_match": [
		{{ range $i, $action := .Actions -}}
		  {{ if gt $i 0 }},{{ end }}
		  "{{ $action }}"
		{{- end }}
		]
	  {{- end }}
	}
  ]
}
`))

var testArachniRulePairTmpl = template.Must(template.New("").Parse(`
{
	"version": "2.1",
  "rules": [
	{
	  "id": "ua0-600-12x-A",
	  "name": "Arachni-A",
	  "tags": {
			"type": "security_scanner",
			"category": "attack_attempt"
	  },
	  "conditions": [{
		  "operator": "match_regex",
		  "parameters": {
			"inputs": [
				{ "address": "{{ .Input1.Address }}"{{ if ne (len .Input1.KeyPath) 0 }},  "key_path": [ {{ range $i, $path := .Input1.KeyPath }}{{ if gt $i 0 }}, {{ end }}"{{ $path }}"{{ end }} ]{{ end }} }
			],
			"regex": "^Arachni-1"
		  }
		}],
	  "transformers": []
	  {{- if .Actions }},
		"on_match": [
		{{ range $i, $action := .Actions -}}
		  {{ if gt $i 0 }},{{ end }}
		  "{{ $action }}"
		{{- end }}
		]
	  {{- end }}
	},
	{
	  "id": "ua0-600-12x-B",
	  "name": "Arachni-B",
	  "tags": {
			"type": "xss",
			"category": "attack_attempt"
	  },
	  "conditions": [{
		  "operator": "match_regex",
		  "parameters": {
			"inputs": [
				{ "address": "{{ .Input2.Address }}"{{ if ne (len .Input2.KeyPath) 0 }},  "key_path": [ {{ range $i, $path := .Input2.KeyPath }}{{ if gt $i 0 }}, {{ end }}"{{ $path }}"{{ end }} ]{{ end }} }
			],
			"regex": "^Arachni-2"
		  }
		}],
	  "transformers": []
	  {{- if .Actions }},
		"on_match": [
		{{ range $i, $action := .Actions -}}
		  {{ if gt $i 0 }},{{ end }}
		  "{{ $action }}"
		{{- end }}
		]
	  {{- end }}
	}
  ]
}
`))

type ruleInput struct {
	Address string
	KeyPath []string
}

func newArachniTestRule(inputs []ruleInput, actions []string) map[string]any {
	var buf bytes.Buffer
	if err := testArachniRuleTmpl.Execute(&buf, struct {
		Inputs  []ruleInput
		Actions []string
	}{Inputs: inputs, Actions: actions}); err != nil {
		panic(err)
	}
	parsed := map[string]any{}

	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		panic(err)
	}

	return parsed
}

func newArachniTestRulePair(input1, input2 ruleInput) map[string]any {
	var buf bytes.Buffer
	if err := testArachniRulePairTmpl.Execute(&buf, struct {
		Input1  ruleInput
		Input2  ruleInput
		Actions []string
	}{input1, input2, nil}); err != nil {
		panic(err)
	}

	parsed := map[string]any{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		panic(err)
	}

	return parsed
}

func newDefaultHandle(rule any) (*Handle, *Diagnostics, error) {
	builder, err := NewBuilder()
	if err != nil {
		return nil, nil, err
	}

	diag, err := builder.AddOrUpdateConfig("/default", rule)
	if err != nil {
		return nil, nil, err
	}

	return builder.Build(), &diag, nil
}

func maxWafValueEncoder(cfg EncoderConfig) map[string]any {
	rnd := rand.New(rand.NewSource(33))
	buf := make([]byte, bindings.MaxStringLength)
	rnd.Read(buf)
	fullstr := string(buf)

	return maxWafValueRec(&cfg, fullstr, int(cfg.MaxObjectDepth))
}

func maxWafValueRec(cfg *EncoderConfig, str string, depth int) map[string]any {
	data := make(map[string]any, cfg.MaxContainerSize)

	if depth == 0 {
		for i := 0; i < int(cfg.MaxContainerSize); i++ {
			data[str+strconv.Itoa(i)] = str
		}
		return data
	}

	for i := 0; i < int(cfg.MaxContainerSize); i++ {
		data[str+strconv.Itoa(i)] = maxWafValueRec(cfg, str, depth-1)
	}
	return data
}

func TestTimeout(t *testing.T) {
	waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	require.NotNil(t, waf)

	largeValue := map[string]any{
		"my.input": maxWafValueEncoder(EncoderConfig{
			MaxContainerSize: 64,
			MaxObjectDepth:   2,
			MaxStringSize:    512,
		}),
	}

	normalValue := map[string]any{
		"my.input": "Arachni",
	}

	var wafTimerKey timer.Key = "waf"
	var raspTimerKey timer.Key = "rasp"

	t.Run("not-empty-metrics-match", func(t *testing.T) {
		context, err := waf.NewContext(timer.WithBudget(time.Hour), timer.WithComponents(wafTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		res, err := context.Run(RunAddressData{Data: normalValue, TimerKey: wafTimerKey})
		require.NoError(t, err)
		require.NotEmpty(t, context.Timer.Stats())
		require.NotZero(t, context.Timer.Stats()[wafTimerKey])

		require.NotZero(t, res.TimerStats[DecodeTimeKey])
		require.NotZero(t, res.TimerStats[EncodeTimeKey])
		require.NotZero(t, res.TimerStats[DurationTimeKey])
	})

	t.Run("not-empty-metrics-no-match", func(t *testing.T) {
		context, err := waf.NewContext(timer.WithBudget(time.Hour), timer.WithComponents(wafTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		res, err := context.Run(RunAddressData{Data: map[string]any{"my.input": "curl/7.88"}, TimerKey: wafTimerKey})
		require.NoError(t, err)
		require.NotEmpty(t, context.Timer.Stats())
		require.NotZero(t, context.Timer.Stats()[wafTimerKey])

		require.NotZero(t, res.TimerStats[DecodeTimeKey])
		require.NotZero(t, res.TimerStats[EncodeTimeKey])
		require.NotZero(t, res.TimerStats[DurationTimeKey])
	})

	t.Run("timeout-persistent-encoder", func(t *testing.T) {
		context, err := waf.NewContext(timer.WithBudget(time.Millisecond), timer.WithComponents(wafTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		res, err := context.Run(RunAddressData{Data: largeValue, TimerKey: wafTimerKey})
		require.Equal(t, waferrors.ErrTimeout, err)
		require.GreaterOrEqual(t, context.Timer.Stats()[wafTimerKey], time.Millisecond)
		require.GreaterOrEqual(t, res.TimerStats[EncodeTimeKey], time.Millisecond)
	})

	t.Run("timeout-ephemeral-encoder", func(t *testing.T) {
		context, err := waf.NewContext(timer.WithBudget(time.Millisecond), timer.WithComponents(wafTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		// Ephemeral data is passed via SubContext.
		// A subcontext snapshots the parent's remaining budget when it is created,
		// then enforces that budget through its own timer.
		subCtx, err := context.SubContext()
		require.NoError(t, err)
		defer subCtx.Close()

		res, err := subCtx.Run(RunAddressData{Data: largeValue})
		require.Equal(t, waferrors.ErrTimeout, err)
		require.GreaterOrEqual(t, res.TimerStats[EncodeTimeKey], time.Millisecond)
	})

	t.Run("subcontext-budget-is-snapshotted-at-creation", func(t *testing.T) {
		context, err := waf.NewContext(timer.WithBudget(time.Millisecond), timer.WithComponents(wafTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		subCtx, err := context.SubContext()
		require.NoError(t, err)
		defer subCtx.Close()

		_, err = context.Run(RunAddressData{Data: largeValue, TimerKey: wafTimerKey})
		require.Equal(t, waferrors.ErrTimeout, err)

		res, err := subCtx.Run(RunAddressData{Data: normalValue})
		require.NoError(t, err)
		require.Len(t, res.Events, 1)
		require.NotZero(t, res.TimerStats[EncodeTimeKey])
	})

	t.Run("many-runs", func(t *testing.T) {
		context, err := waf.NewContext(timer.WithBudget(time.Millisecond), timer.WithComponents(wafTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		for i := 0; i < 1000 && err != waferrors.ErrTimeout; i++ {
			_, err = context.Run(RunAddressData{Data: normalValue, TimerKey: wafTimerKey})
		}

		require.Equal(t, waferrors.ErrTimeout, err)
	})

	t.Run("rasp-simple", func(t *testing.T) {
		waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
		require.NoError(t, err)
		require.NotNil(t, waf)

		context, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget), timer.WithComponents(wafTimerKey, raspTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		res, err := context.Run(RunAddressData{Data: normalValue, TimerKey: raspTimerKey})
		require.NoError(t, err)
		require.NotEmpty(t, context.Timer.Stats())
		require.NotZero(t, context.Timer.Stats()[raspTimerKey])

		require.NotZero(t, res.TimerStats[DecodeTimeKey])
		require.NotZero(t, res.TimerStats[EncodeTimeKey])
		require.NotZero(t, res.TimerStats[DurationTimeKey])
	})

	t.Run("rasp-timeout", func(t *testing.T) {
		context, err := waf.NewContext(timer.WithBudget(time.Millisecond), timer.WithComponents(wafTimerKey, raspTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		res, err := context.Run(RunAddressData{Data: largeValue, TimerKey: raspTimerKey})
		require.Equal(t, waferrors.ErrTimeout, err)
		require.GreaterOrEqual(t, context.Timer.Stats()[raspTimerKey], time.Millisecond)
		require.GreaterOrEqual(t, res.TimerStats[EncodeTimeKey], time.Millisecond)
	})

	t.Run("both-timeout", func(t *testing.T) {
		// TODO(eliott.bouhana): APPSEC-58637
		t.Skip("TODO(eliott.bouhana): This test is flaky and needs to be fixed")

		context, err := waf.NewContext(timer.WithBudget(time.Millisecond), timer.WithComponents(wafTimerKey, raspTimerKey))
		require.NoError(t, err)
		require.NotNil(t, context)
		defer context.Close()

		res, err := context.Run(RunAddressData{Data: normalValue, TimerKey: wafTimerKey})
		require.NoError(t, err)
		require.NotEmpty(t, context.Timer.Stats())
		require.NotZero(t, context.Timer.Stats()[wafTimerKey])

		require.NotZero(t, res.TimerStats[DecodeTimeKey])
		require.NotZero(t, res.TimerStats[EncodeTimeKey])
		require.NotZero(t, res.TimerStats[DurationTimeKey])

		res, err = context.Run(RunAddressData{Data: largeValue, TimerKey: raspTimerKey})
		require.Equal(t, waferrors.ErrTimeout, err)
		require.LessOrEqual(t, context.Timer.Stats()[wafTimerKey], time.Millisecond)
		require.GreaterOrEqual(t, context.Timer.Stats()[raspTimerKey]+context.Timer.Stats()[wafTimerKey], time.Millisecond)
		require.GreaterOrEqual(t, context.Timer.Stats()[raspTimerKey]+res.TimerStats[EncodeTimeKey], time.Millisecond)
	})
}

func TestMatching(t *testing.T) {
	waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	require.NotNil(t, waf)

	require.Equal(t, []string{"my.input"}, waf.Addresses())

	wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	require.NotNil(t, wafCtx)

	// Not matching because the address value doesn't match the rule
	values := map[string]any{
		"my.input": "go client",
	}
	res, err := wafCtx.Run(RunAddressData{Data: values})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching because the address is not used by the rule
	values = map[string]any{
		"server.request.uri.raw": "something",
	}
	res, err = wafCtx.Run(RunAddressData{Data: values})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Matching
	// Note a WAF rule can only match once. This is why we test the matching case at the end.
	values = map[string]any{
		"my.input": "Arachni",
	}
	res, err = wafCtx.Run(RunAddressData{Data: values})
	require.NoError(t, err)
	require.NotEmpty(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching anymore since it already matched before
	res, err = wafCtx.Run(RunAddressData{Data: values})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Nil values
	res, err = wafCtx.Run(RunAddressData{})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Empty values
	res, err = wafCtx.Run(RunAddressData{Data: map[string]any{}})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	wafCtx.Close()
	waf.Close()
	// Using the WAF instance after it was closed leads to a nil WAF context
	ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.Nil(t, ctx)
	require.Error(t, err)
}

func TestMatchingEphemeralAndPersistent(t *testing.T) {
	// This test validates the WAF behavior when a given address is provided as both
	// persistent (on root context) and ephemeral (on subcontext).
	waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	defer waf.Close()

	wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	require.NotNil(t, wafCtx)
	defer wafCtx.Close()

	// Persistent data is run first on the root context
	res, err := wafCtx.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni/persistent"}})
	require.NoError(t, err)

	// There is only one hit here on the PERSISTENT value
	require.Len(t, res.Events, 1)
	event := res.Events[0].(map[string]any)
	require.Equal(t,
		[]any{map[string]any{
			"operator":       "match_regex",
			"operator_value": "^Arachni",
			"parameters": []any{map[string]any{
				"address":   "my.input",
				"highlight": []any{"Arachni"},
				"key_path":  []any{},
				"value":     "Arachni/persistent", // <-- The important bit, really
			}},
		}},
		event["rule_matches"],
	)

	// Ephemeral data is run on a subcontext
	subCtx, err := wafCtx.SubContext()
	require.NoError(t, err)
	defer subCtx.Close()

	res, err = subCtx.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni/ephemeral"}})
	require.NoError(t, err)
	// There shouldn't be any match since the rule already matched with persistent data
	require.Empty(t, res.Events)
}

func TestMatchingEphemeral(t *testing.T) {
	const (
		input1 = "my.input.1"
		input2 = "my.input.2"
	)

	waf, _, err := newDefaultHandle(newArachniTestRulePair(ruleInput{Address: input1}, ruleInput{Address: input2}))
	require.NoError(t, err)
	require.NotNil(t, waf)

	addrs := waf.Addresses()
	sort.Strings(addrs)
	require.Equal(t, []string{input1, input2}, addrs)

	wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	require.NotNil(t, wafCtx)

	// First run persistent data (input2), then ephemeral via subcontext (input1)
	// Not matching because the address value doesn't match the rule
	res, err := wafCtx.Run(RunAddressData{Data: map[string]any{input2: "go client"}})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	subCtx, err := wafCtx.SubContext()
	require.NoError(t, err)
	res, err = subCtx.Run(RunAddressData{Data: map[string]any{input1: "go client"}})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)
	subCtx.Close()

	// Not matching because the address is not used by the rule
	res, err = wafCtx.Run(RunAddressData{Data: map[string]any{"server.request.body.raw": "something"}})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	subCtx, err = wafCtx.SubContext()
	require.NoError(t, err)
	res, err = subCtx.Run(RunAddressData{Data: map[string]any{"server.request.uri.raw": "something"}})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)
	subCtx.Close()

	// Matching: persistent data (input2) on root context
	res, err = wafCtx.Run(RunAddressData{Data: map[string]any{input2: "Arachni-2"}})
	require.NoError(t, err)
	require.Len(t, res.Events, 1) // 1 persistent
	require.Nil(t, res.Actions)

	// Matching: ephemeral data (input1) on subcontext
	// Note a WAF rule with ephemeral addresses may match more than once!
	subCtx, err = wafCtx.SubContext()
	require.NoError(t, err)
	res, err = subCtx.Run(RunAddressData{Data: map[string]any{input1: "Arachni-1"}})
	require.NoError(t, err)
	require.Len(t, res.Events, 1) // 1 ephemeral
	require.Nil(t, res.Actions)
	subCtx.Close()

	// Run persistent again - shouldn't match anymore since it already matched
	res, err = wafCtx.Run(RunAddressData{Data: map[string]any{input2: "Arachni-2"}})
	require.NoError(t, err)
	require.Empty(t, res.Events) // persistent already matched
	require.Nil(t, res.Actions)

	// Ephemeral address should still match on new subcontext
	subCtx, err = wafCtx.SubContext()
	require.NoError(t, err)
	res, err = subCtx.Run(RunAddressData{Data: map[string]any{input1: "Arachni-1"}})
	require.NoError(t, err)
	require.Len(t, res.Events, 1) // 1 ephemeral - still matches
	require.Nil(t, res.Actions)
	subCtx.Close()

	wafCtx.Close()
	waf.Close()
	// Using the WAF instance after it was closed leads to a nil WAF context
	ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.Nil(t, ctx)
	require.Error(t, err)
}

func TestMatchingEphemeralOnly(t *testing.T) {
	const (
		input1 = "my.input.1"
		input2 = "my.input.2"
	)

	waf, _, err := newDefaultHandle(newArachniTestRulePair(ruleInput{Address: input1}, ruleInput{Address: input2}))
	require.NoError(t, err)
	require.NotNil(t, waf)

	addrs := waf.Addresses()
	sort.Strings(addrs)
	require.Equal(t, []string{input1, input2}, addrs)

	wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	require.NotNil(t, wafCtx)

	// Ephemeral data is run via SubContext
	// Not matching because the address value doesn't match the rule
	subCtx, err := wafCtx.SubContext()
	require.NoError(t, err)
	res, err := subCtx.Run(RunAddressData{Data: map[string]any{input1: "go client"}})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)
	subCtx.Close()

	// Not matching because the address is not used by the rule
	subCtx, err = wafCtx.SubContext()
	require.NoError(t, err)
	res, err = subCtx.Run(RunAddressData{Data: map[string]any{"server.request.uri.raw": "something"}})
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)
	subCtx.Close()

	// Matching
	subCtx, err = wafCtx.SubContext()
	require.NoError(t, err)
	res, err = subCtx.Run(RunAddressData{Data: map[string]any{input1: "Arachni-1"}})
	require.NoError(t, err)
	require.Len(t, res.Events, 1) // 1 ephemeral
	require.Nil(t, res.Actions)
	subCtx.Close()

	wafCtx.Close()
	waf.Close()
	// Using the WAF instance after it was closed leads to a nil WAF context
	ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.Nil(t, ctx)
	require.Error(t, err)
}

func TestSubContext(t *testing.T) {
	waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	require.NotNil(t, waf)
	defer waf.Close()

	t.Run("subcontext-from-subcontext-creates-a-sibling", func(t *testing.T) {
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		defer ctx.Close()

		// Create first subcontext
		subCtx1, err := ctx.SubContext()
		require.NoError(t, err)
		defer subCtx1.Close()

		res, err := subCtx1.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni"}})
		require.NoError(t, err)
		require.Len(t, res.Events, 1)

		// Creating a subcontext from another subcontext intentionally creates a new
		// sibling from the shared root WAF context. It does not inherit subCtx1's
		// ephemeral state, so the same ephemeral match can happen again.
		subCtx2, err := subCtx1.SubContext()
		require.NoError(t, err)
		defer subCtx2.Close()

		res, err = subCtx2.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni"}})
		require.NoError(t, err)
		require.Len(t, res.Events, 1)
	})

	t.Run("subcontext-on-closed-context", func(t *testing.T) {
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)

		ctx.Close()

		// Creating subcontext from closed context should fail
		subCtx, err := ctx.SubContext()
		require.Error(t, err)
		require.Nil(t, subCtx)
	})

	t.Run("multiple-subcontexts", func(t *testing.T) {
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		defer ctx.Close()

		// Create multiple subcontexts
		subCtx1, err := ctx.SubContext()
		require.NoError(t, err)

		subCtx2, err := ctx.SubContext()
		require.NoError(t, err)

		subCtx3, err := ctx.SubContext()
		require.NoError(t, err)

		// All should work independently
		res1, err := subCtx1.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni-1"}})
		require.NoError(t, err)
		require.Len(t, res1.Events, 1)

		res2, err := subCtx2.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni-2"}})
		require.NoError(t, err)
		require.Len(t, res2.Events, 1)

		res3, err := subCtx3.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni-3"}})
		require.NoError(t, err)
		require.Len(t, res3.Events, 1)

		subCtx1.Close()
		subCtx2.Close()
		subCtx3.Close()
	})

	t.Run("subcontext-data-isolation", func(t *testing.T) {
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		defer ctx.Close()

		// Run data on subcontext
		subCtx, err := ctx.SubContext()
		require.NoError(t, err)

		res, err := subCtx.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni"}})
		require.NoError(t, err)
		require.Len(t, res.Events, 1)

		subCtx.Close()

		// New subcontext should still match (data didn't persist)
		subCtx2, err := ctx.SubContext()
		require.NoError(t, err)

		res2, err := subCtx2.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni"}})
		require.NoError(t, err)
		require.Len(t, res2.Events, 1) // Still matches because subcontext data is isolated

		subCtx2.Close()
	})

	t.Run("subcontext-close-then-run-returns-error", func(t *testing.T) {
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)

		subCtx, err := ctx.SubContext()
		require.NoError(t, err)

		subCtx.Close()

		// Run on closed subcontext should return an error
		_, err = subCtx.Run(RunAddressData{Data: map[string]any{"my.input": "Arachni"}})
		require.ErrorIs(t, err, waferrors.ErrContextClosed)

		ctx.Close()
	})

	t.Run("run-on-closed-subcontext", func(t *testing.T) {
		ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		defer ctx.Close()

		subCtx, err := ctx.SubContext()
		require.NoError(t, err)

		subCtx.Close()

		// Running on closed subcontext should fail
		res, err := subCtx.Run(RunAddressData{Data: map[string]any{"my.input": "test"}})
		require.Error(t, err)
		require.Empty(t, res.Events)
	})
}

func TestActions(t *testing.T) {
	testActions := func(expectedActions []string, expectedActionsTypes []string) func(t *testing.T) {
		return func(t *testing.T) {
			waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, expectedActions))
			require.NoError(t, err)
			require.NotNil(t, waf)
			defer waf.Close()

			wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
			require.NoError(t, err)
			require.NotNil(t, wafCtx)
			defer wafCtx.Close()

			// Matching the Arachni pattern
			values := map[string]any{
				"my.input": "Arachni",
			}
			res, err := wafCtx.Run(RunAddressData{Data: values})
			require.NoError(t, err)
			require.NotEmpty(t, res.Events)
			for _, aType := range expectedActionsTypes {
				require.Contains(t, res.Actions, aType)
			}
			if action, ok := res.Actions["block_request"]; ok {
				actionMap, ok := action.(map[string]any)
				require.True(t, ok)
				securityResponseID, ok := actionMap["security_response_id"].(string)
				require.True(t, ok)
				require.NotEmpty(t, securityResponseID)
			}
		}
	}

	t.Run("single", testActions([]string{"block"}, []string{"block_request"}))
	t.Run("multiple-actions", testActions([]string{"block", "extract_schema"}, []string{"block_request", "generate_schema"}))
}

func TestAddresses(t *testing.T) {
	expectedAddresses := []string{"my.indexed.input", "my.third.input", "my.second.input", "my.first.input"}
	addresses := []ruleInput{{Address: "my.first.input"}, {Address: "my.second.input"}, {Address: "my.third.input"}, {Address: "my.indexed.input", KeyPath: []string{"indexed"}}}
	waf, _, err := newDefaultHandle(newArachniTestRule(addresses, nil))
	require.NoError(t, err)
	defer waf.Close()
	require.Equal(t, expectedAddresses, waf.Addresses())
}

func TestKnownActions(t *testing.T) {
	waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.first.input"}}, []string{"block"}))
	require.NoError(t, err)
	defer waf.Close()
	require.Equal(t, []string{"block_request"}, waf.Actions())
}

func TestConcurrency(t *testing.T) {

	// Start 200 goroutines that will use the WAF 500 times each
	nbUsers := 200
	nbRun := 500

	t.Run("concurrent-waf-context-usage", func(t *testing.T) {
		waf, _, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)
		defer waf.Close()
		errCh := make(chan error, nbUsers)

		wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		defer wafCtx.Close()

		// User agents that won't match the rule so that it doesn't get pruned.
		// Said otherwise, the User-Agent rule will run as long as it doesn't match, otherwise it gets ignored.
		// This is the reason why the following user agent are not Arachni.
		userAgents := [...]string{"Foo", "Bar", "Datadog"}
		length := len(userAgents)

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch and
		// increase the chances of parallel accesses
		startBarrier.Add(1)
		// Create a stopBarrier to signal when all user goroutines are done.
		stopBarrier.Add(nbUsers)

		for range nbUsers {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning

				if err := captureWorkerError(func() error {
					for c := range nbRun {
						i := c % length
						data := map[string]any{
							"server.request.headers.no_cookies": map[string]string{
								"user-agent": userAgents[i],
							},
						}
						res, err := wafCtx.Run(RunAddressData{Data: data})
						if err != nil {
							return err
						}
						if len(res.Events) > 0 {
							return fmt.Errorf("c=%d events=`%v`", c, res.Events)
						}
					}
					return nil
				}); err != nil {
					errCh <- err
				}
			}()
		}

		// Save the test start time to compare it to the first metricsStore store's
		// that should be latter.
		startBarrier.Done() // Unblock the user goroutines
		stopBarrier.Wait()  // Wait for the user goroutines to be done

		// Test the rule matches Arachni in the end
		data := map[string]any{
			"server.request.headers.no_cookies": map[string]string{
				"user-agent": "Arachni",
			},
		}
		res, err := wafCtx.Run(RunAddressData{Data: data})
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
		close(errCh)
		for err := range errCh {
			require.NoError(t, err)
		}
	})

	t.Run("concurrent-waf-instance-usage", func(t *testing.T) {
		waf, _, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)
		defer waf.Close()
		errCh := make(chan error, nbUsers)

		// User agents that won't match the rule so that it doesn't get pruned.
		// Said otherwise, the User-Agent rule will run as long as it doesn't match, otherwise it gets ignored.
		// This is the reason why the following user agent are not Arachni.
		userAgents := [...]string{"Foo", "Bar", "Datadog"}
		length := len(userAgents)

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch and
		// increase the chances of parallel accesses
		startBarrier.Add(1)
		// Create a stopBarrier to signal when all user goroutines are done.
		stopBarrier.Add(nbUsers)

		for range nbUsers {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning

				wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
				if err != nil {
					errCh <- fmt.Errorf("NewContext failed: %w", err)
					return
				}
				defer wafCtx.Close()

				if err := captureWorkerError(func() error {
					for c := range nbRun {
						i := c % length
						data := map[string]any{
							"server.request.headers.no_cookies": map[string]string{
								"user-agent": userAgents[i],
							},
						}
						res, err := wafCtx.Run(RunAddressData{Data: data})
						if err != nil {
							return err
						}
						if len(res.Events) > 0 {
							return fmt.Errorf("c=%d events=`%v`", c, res.Events)
						}
					}

					// Test the rule matches Arachni in the end
					data := map[string]any{
						"server.request.headers.no_cookies": map[string]string{
							"user-agent": "Arachni",
						},
					}
					res, err := wafCtx.Run(RunAddressData{Data: data})
					if err != nil {
						return fmt.Errorf("Run failed: %w", err)
					}
					if len(res.Events) == 0 {
						return fmt.Errorf("expected events after final run")
					}
					if res.Actions != nil {
						return fmt.Errorf("expected nil actions, got %v", res.Actions)
					}
					return nil
				}); err != nil {
					errCh <- err
				}
			}()
		}

		// Save the test start time to compare it to the first metricsStore store's
		// that should be latter.
		startBarrier.Done() // Unblock the user goroutines
		stopBarrier.Wait()  // Wait for the user goroutines to be done
		close(errCh)
		for err := range errCh {
			require.NoError(t, err)
		}
	})

	t.Run("concurrent-waf-subcontext-usage", func(t *testing.T) {
		waf, _, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)
		defer waf.Close()
		errCh := make(chan error, nbUsers)

		// User agents that won't match the rule so that it doesn't get pruned.
		// Said otherwise, the User-Agent rule will run as long as it doesn't match, otherwise it gets ignored.
		// This is the reason why the following user agent are not Arachni.
		userAgents := [...]string{"Foo", "Bar", "Datadog"}
		length := len(userAgents)

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch and
		// increase the chances of parallel accesses
		startBarrier.Add(1)
		// Create a stopBarrier to signal when all user goroutines are done.
		stopBarrier.Add(nbUsers)

		for range nbUsers {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning

				wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
				if err != nil {
					errCh <- fmt.Errorf("NewContext failed: %w", err)
					return
				}
				defer wafCtx.Close()

				wafSubCtx, err := wafCtx.SubContext()
				if err != nil {
					errCh <- fmt.Errorf("SubContext failed: %w", err)
					return
				}
				defer wafSubCtx.Close()

				if err := captureWorkerError(func() error {
					for c := range nbRun {
						i := c % length
						data := map[string]any{
							"server.request.headers.no_cookies": map[string]string{
								"user-agent": userAgents[i],
							},
						}

						res, err := wafSubCtx.Run(RunAddressData{Data: data})
						if err != nil {
							return err
						}
						if len(res.Events) > 0 {
							return fmt.Errorf("c=%d events=`%v`", c, res.Events)
						}
					}

					// Test the rule matches Arachni in the end
					data := map[string]any{
						"server.request.headers.no_cookies": map[string]string{
							"user-agent": "Arachni",
						},
					}
					res, err := wafSubCtx.Run(RunAddressData{Data: data})
					if err != nil {
						return fmt.Errorf("SubContext Run failed: %w", err)
					}
					if len(res.Events) == 0 {
						return fmt.Errorf("expected events after final subcontext run")
					}
					if res.Actions != nil {
						return fmt.Errorf("expected nil actions, got %v", res.Actions)
					}
					return nil
				}); err != nil {
					errCh <- err
				}
			}()
		}

		// Save the test start time to compare it to the first metricsStore store's
		// that should be latter.
		startBarrier.Done() // Unblock the user goroutines
		stopBarrier.Wait()  // Wait for the user goroutines to be done
		close(errCh)
		for err := range errCh {
			require.NoError(t, err)
		}
	})

	t.Run("concurrent-waf-handle-close", func(t *testing.T) {
		// Test that the reference counter of a WAF handle is properly
		// implemented by running many WAF context creations/deletion
		// concurrently with their WAF handle closing.
		// This test's execution order is not deterministic and simply tries to
		// maximize the chances to highlight ref-counter problems, in particular
		// the special ref-counter case where the WAF handle gets completely
		// released when it reaches 0.
		waf, _, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch and
		// increase the chances of parallel accesses
		startBarrier.Add(1)
		// Create a stopBarrier to signal when all user goroutines are done.
		stopBarrier.Add(nbUsers + 1) // +1 is the goroutine closing the WAF handle

		// Goroutines concurrently creating and destroying WAF contexts so that
		// the WAF handle ref-counter gets stressed out.
		for range nbUsers {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning

				wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
				if wafCtx == nil || err != nil {
					return
				}
				wafCtx.Close()
			}()
		}

		// Single goroutine closing the WAF handle
		go func() {
			startBarrier.Wait()      // Sync the starts of the goroutines
			defer stopBarrier.Done() // Signal we are done when returning
			time.Sleep(time.Microsecond)
			waf.Close()
		}()

		// Save the test start time to compare it to the first metricsStore store's
		// that should be latter.
		startBarrier.Done() // Unblock the user goroutines
		stopBarrier.Wait()  // Wait for the user goroutines to be done

		// The test mustn't crash and ref-counter must be 0
		require.Zero(t, waf.refCounter.Load())
	})

	t.Run("concurrent-context-use-destroy", func(t *testing.T) {
		// This test validates that the WAF Context can be used from multiple
		// threads, with mixed calls to `ddwaf_run` and `ddwaf_context_destroy`,
		// which are not thread-safe.
		waf, _, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)

		wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		require.NotNil(t, wafCtx)
		errCh := make(chan error, nbUsers)

		var startBarrier, stopBarrier sync.WaitGroup
		startBarrier.Add(1)
		stopBarrier.Add(nbUsers + 1)

		data := map[string]any{
			"server.request.headers.no_cookies": map[string][]string{
				"user-agent": {"Arachni/test"},
			},
		}

		for n := range nbUsers {
			go func() {
				startBarrier.Wait()
				defer stopBarrier.Done()

				// A microsecond sleep gives us some scheduler-backed order of execution randomization
				time.Sleep(time.Microsecond)

				// Half of these goroutines will try to use wafCtx.Run(...), while the other half will try
				// to use wafCtx.Close(). The expected outcome is that exactly one call to wafCtx.Close()
				// effectively releases the WAF context, and between 0 and N calls to wafCtx.Run(...) are
				// done (those that land after `wafCtx.Close()` happened will be silent no-ops).
				if n%2 == 0 {
					// Use SubContext for ephemeral data
					subCtx, err := wafCtx.SubContext()
					if err != nil {
						if !errors.Is(err, waferrors.ErrContextClosed) {
							errCh <- fmt.Errorf("SubContext failed with unexpected error: %w", err)
						}
						return
					}
					_, err = subCtx.Run(RunAddressData{Data: data})
					if err != nil {
						if !errors.Is(err, waferrors.ErrContextClosed) {
							errCh <- fmt.Errorf("Run failed with unexpected error: %w", err)
						}
					}
					subCtx.Close()
				} else {
					wafCtx.Close()
				}
			}()
		}

		go func() {
			startBarrier.Wait()
			defer stopBarrier.Done()

			// A microsecond sleep gives us some scheduler-backed order of execution randomization
			time.Sleep(time.Microsecond)

			// We also asynchronously release the WAF handle, which is fine to do as the WAF context is
			// still in use, as the WAF handle has a reference counter guarding it's destruction.
			waf.Close()
		}()

		startBarrier.Done()
		stopBarrier.Wait()
		close(errCh)
		for err := range errCh {
			require.NoError(t, err)
		}

		// Verify the WAF Handle was properly released.
		require.Zero(t, waf.refCounter.Load())
	})
}

func TestRunError(t *testing.T) {
	for _, tc := range []struct {
		Err            error
		ExpectedString string
	}{
		{
			Err:            waferrors.ErrInternal,
			ExpectedString: "internal waf error",
		},
		{
			Err:            waferrors.ErrTimeout,
			ExpectedString: "waf timeout",
		},
		{
			Err:            waferrors.ErrInvalidObject,
			ExpectedString: "invalid waf object",
		},
		{
			Err:            waferrors.ErrInvalidArgument,
			ExpectedString: "invalid waf argument",
		},
		{
			Err:            waferrors.ErrOutOfMemory,
			ExpectedString: "out of memory",
		},
		{
			Err:            waferrors.RunError(33),
			ExpectedString: "unknown waf error 33",
		},
	} {
		t.Run(tc.ExpectedString, func(t *testing.T) {
			require.Equal(t, tc.ExpectedString, tc.Err.Error())
		})
	}
}

func TestUnwrapWafResult_TimeoutFromResultMap(t *testing.T) {
	t.Run("timeout-true-returns-ErrTimeout", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var result bindings.WAFObject
		kvs := result.SetMap(&pinner, 1)
		kvs[0].Key.SetString(&pinner, "timeout")
		kvs[0].Val.SetBool(true)
		result.SetMapSize(1)

		_, _, err := unwrapWafResult(bindings.WAFOK, &result)
		require.ErrorIs(t, err, waferrors.ErrTimeout)
	})

	t.Run("timeout-false-returns-no-error", func(t *testing.T) {
		var pinner runtime.Pinner
		defer pinner.Unpin()

		var result bindings.WAFObject
		kvs := result.SetMap(&pinner, 1)
		kvs[0].Key.SetString(&pinner, "timeout")
		kvs[0].Val.SetBool(false)
		result.SetMapSize(1)

		_, _, err := unwrapWafResult(bindings.WAFOK, &result)
		require.NoError(t, err)
	})
}

func TestMetrics(t *testing.T) {
	rules := `{
  "version": "2.1",
  "metadata": {
	"rules_version": "1.2.7"
  },
  "rules": [
	{
	  "id": "valid-rule",
	  "name": "Unicode Full/Half Width Abuse Attack Attempt",
	  "tags": {
		"type": "http_protocol_violation"
	  },
	  "conditions": [
		{
		  "parameters": {
			"inputs": [
			  {
				"address": "server.request.uri.raw"
			  }
			],
			"regex": "\\%u[fF]{2}[0-9a-fA-F]{2}"
		  },
		  "operator": "match_regex"
		}
	  ],
	  "transformers": []
	},
	{
	  "id": "missing-tags-1",
	  "name": "Unicode Full/Half Width Abuse Attack Attempt",
	  "conditions": [
	  ],
	  "transformers": []
	},
	{
	  "id": "missing-tags-2",
	  "name": "Unicode Full/Half Width Abuse Attack Attempt",
	  "conditions": [
	  ],
	  "transformers": []
	},
	{
	  "id": "missing-name",
	  "tags": {
		"type": "http_protocol_violation"
	  },
	  "conditions": [
	  ],
	  "transformers": []
	}
  ],
  "actions": [
    {
      "id": "block",
      "type": "block_request",
      "parameters": {
        "status_code": 403,
        "type": "auto"
      }
    },
    {
      "id": "redirect",
      "type": "redirect_request",
      "parameters": {
        "status_code": 303,
        "location": "/tmp"
      }
    },
    {
      "id": "block2"
    }
  ]
}
`
	var parsed any

	require.NoError(t, json.Unmarshal([]byte(rules), &parsed))

	waf, diags, err := newDefaultHandle(parsed)
	require.NoError(t, err)
	defer waf.Close()

	var wafTimerKey timer.Key = "waf"

	t.Run("Diagnostics", func(t *testing.T) {
		require.NotNil(t, diags.Rules)
		require.Len(t, diags.Rules.Failed, 3)
		for _, id := range []string{"missing-tags-1", "missing-tags-2", "missing-name"} {
			require.Contains(t, diags.Rules.Failed, id)
		}
		require.Len(t, diags.Rules.Loaded, 1)
		require.Contains(t, diags.Rules.Loaded, "valid-rule")
		require.Equal(t, diags.Version, "1.2.7")
		require.Len(t, diags.Rules.Errors, 1)

		// Action diagnostics
		require.Len(t, diags.Actions.Loaded, 2)
		require.Len(t, diags.Actions.Failed, 1)
		require.Contains(t, diags.Actions.Loaded, "block")
		require.Contains(t, diags.Actions.Loaded, "redirect")
		require.Contains(t, diags.Actions.Failed, "block2")
	})

	t.Run("RunDuration", func(t *testing.T) {
		wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget), timer.WithComponents(wafTimerKey))
		require.NoError(t, err)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		// Craft matching data to force work on the WAF
		data := map[string]any{
			"server.request.uri.raw": "\\%uff00",
		}
		start := time.Now()
		res, err := wafCtx.Run(RunAddressData{Data: data, TimerKey: wafTimerKey})
		elapsedNS := time.Since(start).Nanoseconds()
		require.NoError(t, err)
		require.NotNil(t, res.Events)
		require.Nil(t, res.Actions)

		// Make sure that WAF runtime was set
		overall, internal := wafCtx.Timer.Stats()[wafTimerKey], res.TimerStats[DurationTimeKey]
		require.Greater(t, overall, time.Duration(0))
		require.Greater(t, internal, time.Duration(0))
		require.Greater(t, overall, internal)
		require.LessOrEqual(t, overall, time.Duration(elapsedNS))
	})

	t.Run("Timeouts", func(t *testing.T) {
		wafCtx, err := waf.NewContext(timer.WithBudget(time.Nanosecond), timer.WithComponents(wafTimerKey))
		require.NoError(t, err)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		// Craft matching data to force work on the WAF
		data := map[string]any{
			"server.request.uri.raw": "\\%uff00",
		}

		for i := uint64(1); i <= 10; i++ {
			_, err := wafCtx.Run(RunAddressData{Data: data, TimerKey: wafTimerKey})
			require.Equal(t, waferrors.ErrTimeout, err)
		}
	})
}

func TestObfuscatorConfig(t *testing.T) {
	rule := newArachniTestRule([]ruleInput{{Address: "my.addr", KeyPath: []string{"key"}}}, nil)
	t.Run("key", func(t *testing.T) {
		waf, _, err := newDefaultHandle(rule)
		require.NoError(t, err)
		defer waf.Close()
		wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		data := map[string]any{
			"my.addr": map[string]any{"key": "Arachni-sensitive-Arachni"},
		}
		res, err := wafCtx.Run(RunAddressData{Data: data})
		require.NoError(t, err)
		require.NotNil(t, res.Events)
		require.Nil(t, res.Actions)
		events, err := json.Marshal(res.Events)
		require.NoError(t, err)
		require.NotContains(t, events, "sensitive")
	})

	t.Run("val", func(t *testing.T) {
		waf, _, err := newDefaultHandle(rule)
		require.NoError(t, err)
		defer waf.Close()
		wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		data := map[string]any{
			"my.addr": map[string]any{"key": "Arachni-sensitive-Arachni"},
		}
		res, err := wafCtx.Run(RunAddressData{Data: data})
		require.NoError(t, err)
		require.NotNil(t, res.Events)
		require.Nil(t, res.Actions)
		events, err := json.Marshal(res.Events)
		require.NoError(t, err)
		require.NotContains(t, events, "sensitive")
	})

	t.Run("off", func(t *testing.T) {
		waf, _, err := newDefaultHandle(rule)
		require.NoError(t, err)
		defer waf.Close()
		wafCtx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
		require.NoError(t, err)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		data := map[string]any{
			"my.addr": map[string]any{"key": "Arachni-sensitive-Arachni"},
		}
		res, err := wafCtx.Run(RunAddressData{Data: data})
		require.NoError(t, err)
		require.NotNil(t, res.Events)
		require.Nil(t, res.Actions)
		events, err := json.Marshal(res.Events)
		require.NoError(t, err)
		require.Contains(t, string(events), "sensitive")
	})
}

func TestTruncationInformation(t *testing.T) {
	waf, _, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	defer waf.Close()

	ctx, err := waf.NewContext(timer.WithBudget(timer.UnlimitedBudget))
	require.NoError(t, err)
	defer ctx.Close()

	extra := rand.Intn(10) + 1 // Random int between 1 and 10

	// Run persistent data first
	_, err = ctx.Run(RunAddressData{
		Data: map[string]any{
			"my.input.2": map[string]any{
				"string_too_long":     strings.Repeat("Z", int(bindings.MaxStringLength)+extra+2),
				"container_too_large": make([]bool, int(bindings.MaxContainerSize)+extra+2),
			},
		},
	})
	require.NoError(t, err)

	// Run ephemeral data via SubContext
	subCtx, err := ctx.SubContext()
	require.NoError(t, err)
	defer subCtx.Close()

	_, err = subCtx.Run(RunAddressData{
		Data: map[string]any{
			"my.input": map[string]any{
				"string_too_long":     strings.Repeat("Z", int(bindings.MaxStringLength)+extra),
				"container_too_large": make([]bool, int(bindings.MaxContainerSize)+extra),
			},
		},
	})
	require.NoError(t, err)

	require.Equal(t, map[TruncationReason][]int{
		StringTooLong:     {int(bindings.MaxStringLength) + extra + 2},
		ContainerTooLarge: {int(bindings.MaxContainerSize) + extra + 2},
	}, ctx.truncations)
}

func BenchmarkEncoder(b *testing.B) {
	rnd := rand.New(rand.NewSource(33))
	buf := make([]byte, 16384)
	n, err := rnd.Read(buf)
	fullstr := string(buf)
	encodeTimer, _ := timer.NewTimer(timer.WithUnlimitedBudget())
	var pinner runtime.Pinner
	defer pinner.Unpin()

	for _, l := range []int{1024, 4096, 8192, 16384} {
		encoder, _ := newEncoder(EncoderConfig{
			Pinner:           &pinner,
			MaxObjectDepth:   10,
			MaxStringSize:    math.MaxUint16,
			MaxContainerSize: 100,
			Timer:            encodeTimer,
		})
		b.Run(fmt.Sprintf("%d", l), func(b *testing.B) {
			b.ReportAllocs()
			str := fullstr[:l]
			slice := []string{str, str, str, str, str, str, str, str, str, str}
			data := map[string]any{
				"k0": slice,
				"k1": slice,
				"k2": slice,
				"k3": slice,
				"k4": slice,
				"k5": slice,
				"k6": slice,
				"k7": slice,
				"k8": slice,
				"k9": slice,
			}
			if err != nil || n != len(buf) {
				b.Fatal(err)
			}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := encoder.Encode(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestProcessorOverrides(t *testing.T) {
	rules := `{
	"processor_overrides": [
		{
			"target": [{ "id": "extract-content" }],
			"scanners": {
				"include": [
					{ "id": "test-scanner-001" },
					{ "id": "test-scanner-custom-001" }
				],
				"exclude": []
			}
		}
	],
	"scanners": [
		{
			"id": "test-scanner-custom-001",
			"name": "Custom scanner",
			"key": {
				"operator": "match_regex",
				"parameters": {
					"regex": "\\btestcard\\b",
					"options": { "case_sensitive": false, "min_length": 2 }
				}
			},
			"value": {
				"operator": "match_regex",
				"parameters": {
					"regex": "\\b1234567890\\b",
					"options": { "case_sensitive": false, "min_length": 5 }
				}
			},
			"tags": { "type": "card", "category": "testcategory" }
		}
	]
}`

	builder, err := NewBuilder()
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(rules), &parsed))
	diag, err := builder.AddOrUpdateConfig("/", parsed)
	require.NoError(t, err)
	assert.Equal(t, &Feature{
		Errors:   nil,
		Warnings: nil,
		Error:    "",
		Loaded:   []string{"index:0"},
		Failed:   nil,
		Skipped:  nil,
	}, diag.ProcessorOverrides)
}
