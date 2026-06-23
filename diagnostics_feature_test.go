// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEachFeatureRulesOverrideKey guards against the EachFeature key
// regressing to the plural "rules_overrides": libddwaf and the decoder both
// use the singular "rules_override", so consumers correlating EachFeature
// keys with WAF diagnostic keys must see the singular form.
func TestEachFeatureRulesOverrideKey(t *testing.T) {
	diag := Diagnostics{RulesOverrides: &Feature{}}

	keys := make(map[string]bool)
	diag.EachFeature(func(name string, _ *Feature) {
		keys[name] = true
	})

	assert.True(t, keys["rules_override"], "EachFeature must emit the singular \"rules_override\" key")
	assert.False(t, keys["rules_overrides"], "EachFeature must not emit the plural \"rules_overrides\" key")
}
