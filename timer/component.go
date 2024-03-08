// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"sync/atomic"
	"time"
)

type component struct {
	// name through which the component is identified
	name string
	// Updated each time a run of a sub-timer ends
	spent atomic.Int64
}

func (component *component) addSpent(duration time.Duration) {
	component.spent.Add(int64(duration))
}

// components store the data shared between child timers of the same component name
type components struct {
	lookup  map[string]*component
	storage []component
}

func newComponents(names []string) components {
	lookup := make(map[string]*component, len(names))
	storage := make([]component, len(names))
	for i, name := range names {
		storage[i].name = name
		lookup[name] = &storage[i]
	}
	return components{
		lookup:  lookup,
		storage: storage,
	}
}
