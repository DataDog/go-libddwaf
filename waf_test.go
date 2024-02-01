// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (amd64 || arm64) && (linux || darwin) && !go1.23 && !datadog.no_waf && (cgo || appsec)

package waf

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/DataDog/go-libddwaf/v2/internal/lib"
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

func TestSupportsTarget(t *testing.T) {
	supported, err := SupportsTarget()
	require.True(t, supported)
	require.NoError(t, err)
}

func TestHealth(t *testing.T) {
	supported, err := Health()
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

// Test with a valid JSON but invalid rule format (field "events" should be an array)
const malformedRule = `
{
  "version": "2.1",
  "events": [
	{
	  "id": "ua0-600-12x",
	  "name": "Arachni",
	  "tags": {
		"type": "security_scanner"
	  },
	  "conditions": [
		{
		  "operation": "match_regex",
		  "parameters": {
			"inputs": [
			  { "address": "server.request.headers.no_cookies" }
			],
			"regex": "^Arachni"
		  }
		}
	  ],
	  "transformers": []
	}
  ]
}
`

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

func newDefaultHandle(rule any) (*Handle, error) {
	return NewHandle(rule, "", "")
}

func TestNewWAF(t *testing.T) {
	t.Run("valid-rule", func(t *testing.T) {
		waf, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)
		require.NotNil(t, waf)
		defer waf.Close()
	})

	t.Run("invalid-rule", func(t *testing.T) {
		var parsed any

		require.NoError(t, json.Unmarshal([]byte(malformedRule), &parsed))

		waf, err := newDefaultHandle(parsed)
		require.Error(t, err)
		require.Nil(t, waf)
	})
}

func TestUpdateWAF(t *testing.T) {

	t.Run("valid-rule", func(t *testing.T) {
		waf, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)
		require.NotNil(t, waf)
		defer waf.Close()

		waf2, err := waf.Update(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
		require.NoError(t, err)
		require.NotNil(t, waf2)
		defer waf2.Close()
	})

	t.Run("changes", func(t *testing.T) {
		waf, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
		require.NoError(t, err)
		require.NotNil(t, waf)
		defer waf.Close()

		wafCtx := NewContext(waf)
		defer wafCtx.Close()

		// Matches
		values := map[string]interface{}{
			"my.input": "Arachni",
		}
		ephemeral := map[string]interface{}{
			"my.other.input": map[string]bool{"safe": true},
		}
		res, err := wafCtx.Run(RunAddressData{Persistent: values, Ephemeral: ephemeral}, time.Second)
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
		require.Nil(t, res.Actions)

		// Update
		waf2, err := waf.Update(newArachniTestRule([]ruleInput{{Address: "my.input"}}, []string{"block"}))
		require.NoError(t, err)
		require.NotNil(t, waf2)
		defer waf2.Close()

		wafCtx2 := NewContext(waf2)
		defer wafCtx2.Close()

		// Matches & Block
		values = map[string]interface{}{
			"my.input": "Arachni",
		}
		res, err = wafCtx2.Run(RunAddressData{Persistent: values, Ephemeral: ephemeral}, time.Second)
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
		require.NotEmpty(t, res.Actions)

	})

	t.Run("invalid-rule", func(t *testing.T) {

		waf, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)
		require.NotNil(t, waf)
		defer waf.Close()

		var parsed any

		require.NoError(t, json.Unmarshal([]byte(malformedRule), &parsed))

		waf2, err := waf.Update(parsed)
		require.Error(t, err)
		require.Nil(t, waf2)
	})
}

func TestMatching(t *testing.T) {

	waf, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	require.NotNil(t, waf)

	require.Equal(t, []string{"my.input"}, waf.Addresses())

	wafCtx := NewContext(waf)
	require.NotNil(t, wafCtx)

	// Not matching because the address value doesn't match the rule
	values := map[string]interface{}{
		"my.input": "go client",
	}
	ephemeral := map[string]interface{}{
		"my.other.input": map[string]bool{"safe": true},
	}
	res, err := wafCtx.Run(RunAddressData{Persistent: values, Ephemeral: ephemeral}, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching because the address is not used by the rule
	values = map[string]interface{}{
		"server.request.uri.raw": "something",
	}
	res, err = wafCtx.Run(RunAddressData{Persistent: values, Ephemeral: ephemeral}, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching due to a timeout
	values = map[string]interface{}{
		"my.input": "Arachni",
	}
	res, err = wafCtx.Run(RunAddressData{Persistent: values, Ephemeral: ephemeral}, 0)
	require.Equal(t, ErrTimeout, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Matching
	// Note a WAF rule can only match once. This is why we test the matching case at the end.
	values = map[string]interface{}{
		"my.input": "Arachni",
	}
	res, err = wafCtx.Run(RunAddressData{Persistent: values, Ephemeral: ephemeral}, time.Second)
	require.NoError(t, err)
	require.NotEmpty(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching anymore since it already matched before
	res, err = wafCtx.Run(RunAddressData{Persistent: values, Ephemeral: ephemeral}, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Nil values
	res, err = wafCtx.Run(RunAddressData{}, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Empty values
	res, err = wafCtx.Run(RunAddressData{Persistent: map[string]interface{}{}, Ephemeral: ephemeral}, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	wafCtx.Close()
	waf.Close()
	// Using the WAF instance after it was closed leads to a nil WAF context
	require.Nil(t, NewContext(waf))
}

func TestMatchingEphemeralAndPersistent(t *testing.T) {
	// This test validates the WAF behavior when a given address is provided both as ephemeral and persistent.
	waf, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, nil))
	require.NoError(t, err)
	defer waf.Close()

	wafCtx := NewContext(waf)
	require.NotNil(t, wafCtx)
	defer wafCtx.Close()

	// Intentionally setting the same key on both fields
	addresses := RunAddressData{
		Persistent: map[string]any{"my.input": "Arachni/persistent"},
		Ephemeral:  map[string]any{"my.input": "Arachni/ephemeral"},
	}

	res, err := wafCtx.Run(addresses, time.Second)
	require.NoError(t, err)

	// There is only one hit here
	require.Len(t, res.Events, 1)
	event := res.Events[0].(map[string]any)
	// The hit is on the PERSISTENT value
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

	// Matche the same inputs a second time...
	res, err = wafCtx.Run(addresses, time.Second)
	require.NoError(t, err)
	// There shouldn't be any match anymore...
	require.Empty(t, res.Events)
}

func TestMatchingEphemeral(t *testing.T) {
	const (
		input1 = "my.input.1"
		input2 = "my.input.2"
	)

	waf, err := newDefaultHandle(newArachniTestRulePair(ruleInput{Address: input1}, ruleInput{Address: input2}))
	require.NoError(t, err)
	require.NotNil(t, waf)

	addrs := waf.Addresses()
	sort.Strings(addrs)
	require.Equal(t, []string{input1, input2}, addrs)

	wafCtx := NewContext(waf)
	require.NotNil(t, wafCtx)

	// Not matching because the address value doesn't match the rule
	runAddresses := RunAddressData{
		Ephemeral: map[string]interface{}{
			input1: "go client",
		},
		Persistent: map[string]interface{}{
			input2: "go client",
		},
	}
	res, err := wafCtx.Run(runAddresses, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching because the address is not used by the rule
	runAddresses = RunAddressData{
		Ephemeral: map[string]interface{}{
			"server.request.uri.raw": "something",
		},
		Persistent: map[string]interface{}{
			"server.request.body.raw": "something",
		},
	}
	res, err = wafCtx.Run(runAddresses, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching due to a timeout
	runAddresses = RunAddressData{
		Ephemeral: map[string]interface{}{
			input1: "Arachni-1",
		},
		Persistent: map[string]interface{}{
			input2: "Arachni-2",
		},
	}
	res, err = wafCtx.Run(runAddresses, 0)
	require.Equal(t, ErrTimeout, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Matching
	// Note a WAF rule with ephemeral addresses may match more than once!
	res, err = wafCtx.Run(runAddresses, time.Second)
	require.NoError(t, err)
	require.Len(t, res.Events, 2) // 1 ephemeral, 1 persistent [!!Only if the rules have a different tags.type value!!]
	require.Nil(t, res.Actions)

	// Ephemeral address should still match, persistent shouldn't anymore
	res, err = wafCtx.Run(runAddresses, time.Second)
	require.NoError(t, err)
	require.Len(t, res.Events, 1) // 1 ephemeral
	require.Nil(t, res.Actions)

	wafCtx.Close()
	waf.Close()
	// Using the WAF instance after it was closed leads to a nil WAF context
	require.Nil(t, NewContext(waf))
}

func TestMatchingEphemeralOnly(t *testing.T) {
	const (
		input1 = "my.input.1"
		input2 = "my.input.2"
	)

	waf, err := newDefaultHandle(newArachniTestRulePair(ruleInput{Address: input1}, ruleInput{Address: input2}))
	require.NoError(t, err)
	require.NotNil(t, waf)

	addrs := waf.Addresses()
	sort.Strings(addrs)
	require.Equal(t, []string{input1, input2}, addrs)

	wafCtx := NewContext(waf)
	require.NotNil(t, wafCtx)

	// Not matching because the address value doesn't match the rule
	runAddresses := RunAddressData{
		Ephemeral: map[string]interface{}{
			input1: "go client",
		},
	}
	res, err := wafCtx.Run(runAddresses, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching because the address is not used by the rule
	runAddresses = RunAddressData{
		Ephemeral: map[string]interface{}{
			"server.request.uri.raw": "something",
		},
	}
	res, err = wafCtx.Run(runAddresses, time.Second)
	require.NoError(t, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Not matching due to a timeout
	runAddresses = RunAddressData{
		Ephemeral: map[string]interface{}{
			input1: "Arachni-1",
		},
	}
	res, err = wafCtx.Run(runAddresses, 0)
	require.Equal(t, ErrTimeout, err)
	require.Nil(t, res.Events)
	require.Nil(t, res.Actions)

	// Matching
	res, err = wafCtx.Run(runAddresses, time.Second)
	require.NoError(t, err)
	require.Len(t, res.Events, 1) // 1 ephemeral
	require.Nil(t, res.Actions)

	wafCtx.Close()
	waf.Close()
	// Using the WAF instance after it was closed leads to a nil WAF context
	require.Nil(t, NewContext(waf))
}

func TestActions(t *testing.T) {
	testActions := func(expectedActions []string) func(t *testing.T) {
		return func(t *testing.T) {

			waf, err := newDefaultHandle(newArachniTestRule([]ruleInput{{Address: "my.input"}}, expectedActions))
			require.NoError(t, err)
			require.NotNil(t, waf)
			defer waf.Close()

			wafCtx := NewContext(waf)
			require.NotNil(t, wafCtx)
			defer wafCtx.Close()

			// Not matching because the address value doesn't match the rule
			values := map[string]interface{}{
				"my.input": "Arachni",
			}
			ephemeral := map[string]interface{}{
				"my.other.input": map[string]bool{"safe": true},
			}
			res, err := wafCtx.Run(RunAddressData{Persistent: values, Ephemeral: ephemeral}, time.Second)
			require.NoError(t, err)
			require.NotEmpty(t, res.Events)
			// FIXME: check with libddwaf why the order of returned actions is not kept the same
			require.ElementsMatch(t, expectedActions, res.Actions)
		}
	}

	t.Run("single", testActions([]string{"block"}))
	t.Run("multiple-actions", testActions([]string{"action 1", "action 2", "action 3"}))
}

func TestAddresses(t *testing.T) {
	expectedAddresses := []string{"my.indexed.input", "my.third.input", "my.second.input", "my.first.input"}
	addresses := []ruleInput{{Address: "my.first.input"}, {Address: "my.second.input"}, {Address: "my.third.input"}, {Address: "my.indexed.input", KeyPath: []string{"indexed"}}}
	waf, err := newDefaultHandle(newArachniTestRule(addresses, nil))
	require.NoError(t, err)
	defer waf.Close()
	require.Equal(t, expectedAddresses, waf.Addresses())
}

func TestConcurrency(t *testing.T) {
	// Start 200 goroutines that will use the WAF 500 times each
	nbUsers := 200
	nbRun := 500

	t.Run("concurrent-waf-context-usage", func(t *testing.T) {
		waf, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)
		defer waf.Close()

		wafCtx := NewContext(waf)
		defer wafCtx.Close()

		// User agents that won't match the rule so that it doesn't get pruned.
		// Said otherwise, the User-Agent rule will run as long as it doesn't match, otherwise it gets ignored.
		// This is the reason why the following user agent are not Arachni.
		userAgents := [...]string{"Foo", "Bar", "Datadog"}
		bodies := [3]map[string]any{
			{"foo": "bar"},
			{"baz": "bat"},
			{"payload": "interesting"},
		}
		length := len(userAgents)

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch and
		// increase the chances of parallel accesses
		startBarrier.Add(1)
		// Create a stopBarrier to signal when all user goroutines are done.
		stopBarrier.Add(nbUsers)

		for n := 0; n < nbUsers; n++ {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning

				for c := 0; c < nbRun; c++ {
					i := c % length
					data := map[string]interface{}{
						"server.request.headers.no_cookies": map[string]string{
							"user-agent": userAgents[i],
						},
					}
					ephemeralData := map[string]interface{}{
						"server.request.body": bodies[i],
					}
					res, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeralData}, time.Minute)
					if err != nil {
						panic(err)
					}
					if len(res.Events) > 0 {
						panic(fmt.Errorf("c=%d events=`%v`", c, res.Events))
					}
				}
			}()
		}

		// Save the test start time to compare it to the first metrics store's
		// that should be latter.
		startBarrier.Done() // Unblock the user goroutines
		stopBarrier.Wait()  // Wait for the user goroutines to be done

		// Test the rule matches Arachni in the end
		data := map[string]interface{}{
			"server.request.headers.no_cookies": map[string]string{
				"user-agent": "Arachni",
			},
		}
		ephemeral := map[string]interface{}{
			"server.request.body": map[string]bool{"safe": true},
		}
		res, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeral}, time.Second)
		require.NoError(t, err)
		require.NotEmpty(t, res.Events)
	})

	t.Run("concurrent-waf-instance-usage", func(t *testing.T) {
		waf, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)
		defer waf.Close()

		// User agents that won't match the rule so that it doesn't get pruned.
		// Said otherwise, the User-Agent rule will run as long as it doesn't match, otherwise it gets ignored.
		// This is the reason why the following user agent are not Arachni.
		userAgents := [...]string{"Foo", "Bar", "Datadog"}
		bodies := [3]map[string]any{
			{"foo": "bar"},
			{"baz": "bat"},
			{"payload": "interesting"},
		}
		length := len(userAgents)

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch and
		// increase the chances of parallel accesses
		startBarrier.Add(1)
		// Create a stopBarrier to signal when all user goroutines are done.
		stopBarrier.Add(nbUsers)

		for n := 0; n < nbUsers; n++ {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning

				wafCtx := NewContext(waf)
				defer wafCtx.Close()

				for c := 0; c < nbRun; c++ {
					i := c % length
					data := map[string]interface{}{
						"server.request.headers.no_cookies": map[string]string{
							"user-agent": userAgents[i],
						},
					}
					ephemeral := map[string]interface{}{"server.request.body": bodies[i]}

					res, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeral}, time.Minute)

					if err != nil {
						panic(err)
					}
					if len(res.Events) > 0 {
						panic(fmt.Errorf("c=%d events=`%v`", c, res.Events))
					}
				}

				// Test the rule matches Arachni in the end
				data := map[string]interface{}{
					"server.request.headers.no_cookies": map[string]string{
						"user-agent": "Arachni",
					},
				}
				ephemeral := map[string]interface{}{
					"server.request.body": map[string]bool{"safe": true},
				}
				res, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeral}, time.Second)
				require.NoError(t, err)
				require.NotEmpty(t, res.Events)
				require.Nil(t, res.Actions)
			}()
		}

		// Save the test start time to compare it to the first metrics store's
		// that should be latter.
		startBarrier.Done() // Unblock the user goroutines
		stopBarrier.Wait()  // Wait for the user goroutines to be done
	})

	t.Run("concurrent-waf-handle-close", func(t *testing.T) {
		// Test that the reference counter of a WAF handle is properly
		// implemented by running many WAF context creations/deletion
		// concurrently with their WAF handle closing.
		// This test's execution order is not deterministic and simply tries to
		// maximize the chances to highlight ref-counter problems, in particular
		// the special ref-counter case where the WAF handle gets completely
		// released when it reaches 0.
		waf, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch and
		// increase the chances of parallel accesses
		startBarrier.Add(1)
		// Create a stopBarrier to signal when all user goroutines are done.
		stopBarrier.Add(nbUsers + 1) // +1 is the goroutine closing the WAF handle

		// Goroutines concurrently creating and destroying WAF contexts so that
		// the WAF handle ref-counter gets stressed out.
		for n := 0; n < nbUsers; n++ {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning

				wafCtx := NewContext(waf)
				if wafCtx == nil {
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

		// Save the test start time to compare it to the first metrics store's
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

		waf, err := newDefaultHandle(testArachniRule)
		require.NoError(t, err)

		wafCtx := NewContext(waf)
		require.NotNil(t, wafCtx)

		var startBarrier, stopBarrier sync.WaitGroup
		startBarrier.Add(1)
		stopBarrier.Add(nbUsers + 1)

		data := map[string]any{
			"server.request.headers.no_cookies": map[string][]string{
				"user-agent": {"Arachni/test"},
			},
		}

		for n := 0; n < nbUsers; n++ {
			n := n
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
					wafCtx.Run(RunAddressData{Ephemeral: data}, time.Second)
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
			Err:            ErrInternal,
			ExpectedString: "internal waf error",
		},
		{
			Err:            ErrTimeout,
			ExpectedString: "waf timeout",
		},
		{
			Err:            ErrInvalidObject,
			ExpectedString: "invalid waf object",
		},
		{
			Err:            ErrInvalidArgument,
			ExpectedString: "invalid waf argument",
		},
		{
			Err:            ErrOutOfMemory,
			ExpectedString: "out of memory",
		},
		{
			Err:            RunError(33),
			ExpectedString: "unknown waf error 33",
		},
	} {
		t.Run(tc.ExpectedString, func(t *testing.T) {
			require.Equal(t, tc.ExpectedString, tc.Err.Error())
		})
	}
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
  ]
}
`
	var parsed any

	require.NoError(t, json.Unmarshal([]byte(rules), &parsed))

	waf, err := newDefaultHandle(parsed)
	require.NoError(t, err)
	defer waf.Close()
	t.Run("Diagnostics", func(t *testing.T) {
		require.NotNil(t, waf.diagnostics.Rules)
		require.Len(t, waf.diagnostics.Rules.Failed, 3)
		for _, id := range []string{"missing-tags-1", "missing-tags-2", "missing-name"} {
			require.Contains(t, waf.diagnostics.Rules.Failed, id)
		}
		require.Len(t, waf.diagnostics.Rules.Loaded, 1)
		require.Contains(t, waf.diagnostics.Rules.Loaded, "valid-rule")
		require.Equal(t, waf.diagnostics.Version, "1.2.7")
		require.Len(t, waf.diagnostics.Rules.Errors, 1)
	})

	t.Run("RunDuration", func(t *testing.T) {
		wafCtx := NewContext(waf)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		// Craft matching data to force work on the WAF
		data := map[string]interface{}{
			"server.request.uri.raw": "\\%uff00",
		}
		ephemeral := map[string]interface{}{
			"server.request.body": map[string]bool{"safe": true},
		}
		start := time.Now()
		res, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeral}, time.Second)
		elapsedNS := time.Since(start).Nanoseconds()
		require.NoError(t, err)
		require.NotNil(t, res.Events)
		require.Nil(t, res.Actions)

		// Make sure that WAF runtime was set
		overall, internal := wafCtx.TotalRuntime()
		require.Greater(t, overall, uint64(0))
		require.Greater(t, internal, uint64(0))
		require.Greater(t, overall, internal)
		require.LessOrEqual(t, overall, uint64(elapsedNS))
	})

	t.Run("Timeouts", func(t *testing.T) {
		wafCtx := NewContext(waf)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		// Craft matching data to force work on the WAF
		data := map[string]interface{}{
			"server.request.uri.raw": "\\%uff00",
		}
		ephemeral := map[string]interface{}{
			"server.request.body": map[string]bool{"safe": true},
		}

		for i := uint64(1); i <= 10; i++ {
			_, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeral}, time.Nanosecond)
			require.Equal(t, err, ErrTimeout)
			require.Equal(t, i, wafCtx.TotalTimeouts())
		}
	})
}

func TestObfuscatorConfig(t *testing.T) {
	rule := newArachniTestRule([]ruleInput{{Address: "my.addr", KeyPath: []string{"key"}}}, nil)
	t.Run("key", func(t *testing.T) {
		waf, err := NewHandle(rule, "key", "")
		require.NoError(t, err)
		defer waf.Close()
		wafCtx := NewContext(waf)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		data := map[string]interface{}{
			"my.addr": map[string]interface{}{"key": "Arachni-sensitive-Arachni"},
		}
		ephemeral := map[string]interface{}{
			"server.request.body": map[string]bool{"safe": true},
		}
		res, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeral}, time.Second)
		require.NoError(t, err)
		require.NotNil(t, res.Events)
		require.Nil(t, res.Actions)
		events, err := json.Marshal(res.Events)
		require.NoError(t, err)
		require.NotContains(t, events, "sensitive")
	})

	t.Run("val", func(t *testing.T) {
		waf, err := NewHandle(rule, "", "sensitive")
		require.NoError(t, err)
		defer waf.Close()
		wafCtx := NewContext(waf)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		data := map[string]interface{}{
			"my.addr": map[string]interface{}{"key": "Arachni-sensitive-Arachni"},
		}
		ephemeral := map[string]interface{}{
			"server.request.body": map[string]bool{"safe": true},
		}
		res, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeral}, time.Second)
		require.NoError(t, err)
		require.NotNil(t, res.Events)
		require.Nil(t, res.Actions)
		events, err := json.Marshal(res.Events)
		require.NoError(t, err)
		require.NotContains(t, events, "sensitive")
	})

	t.Run("off", func(t *testing.T) {
		waf, err := NewHandle(rule, "", "")
		require.NoError(t, err)
		defer waf.Close()
		wafCtx := NewContext(waf)
		require.NotNil(t, wafCtx)
		defer wafCtx.Close()
		data := map[string]interface{}{
			"my.addr": map[string]interface{}{"key": "Arachni-sensitive-Arachni"},
		}
		ephemeral := map[string]interface{}{
			"server.request.body": map[string]bool{"safe": true},
		}
		res, err := wafCtx.Run(RunAddressData{Persistent: data, Ephemeral: ephemeral}, time.Second)
		require.NoError(t, err)
		require.NotNil(t, res.Events)
		require.Nil(t, res.Actions)
		events, err := json.Marshal(res.Events)
		require.NoError(t, err)
		require.Contains(t, string(events), "sensitive")
	})
}

func BenchmarkEncoder(b *testing.B) {
	rnd := rand.New(rand.NewSource(33))
	buf := make([]byte, 16384)
	n, err := rnd.Read(buf)
	fullstr := string(buf)
	for _, l := range []int{1024, 4096, 8192, 16384} {
		encoder := encoder{
			objectMaxDepth:   10,
			stringMaxSize:    1 * 1024 * 1024,
			containerMaxSize: 100,
		}
		b.Run(fmt.Sprintf("%d", l), func(b *testing.B) {
			b.ReportAllocs()
			str := fullstr[:l]
			slice := []string{str, str, str, str, str, str, str, str, str, str}
			data := map[string]interface{}{
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
