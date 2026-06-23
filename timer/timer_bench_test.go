// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"runtime"
	"testing"
	"time"
)

func BenchmarkMostUsedFunctions(b *testing.B) {
	b.Run("timer.Start()", func(b *testing.B) {
		var err error
		timers := make([]Timer, b.N)
		for i := range timers {
			timers[i], err = NewTreeTimer(WithBudget(time.Hour))
			if err != nil {
				b.Fatal(err)
			}
		}

		b.ResetTimer()
		for i := range timers {
			runtime.KeepAlive(timers[i].Start())
		}
	})

	b.Run("timer.Spent()", func(b *testing.B) {
		timer, err := NewTreeTimer(WithBudget(time.Hour))
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for b.Loop() {
			runtime.KeepAlive(timer.Spent())
		}
	})

	b.Run("timer.Remaining()", func(b *testing.B) {
		timer, err := NewTreeTimer(WithBudget(time.Hour))
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for b.Loop() {
			runtime.KeepAlive(timer.Remaining())
		}
	})

	b.Run("timer.Exhausted()", func(b *testing.B) {
		timer, err := NewTreeTimer(WithBudget(time.Hour))
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for b.Loop() {
			runtime.KeepAlive(timer.Exhausted())
		}
	})
}
