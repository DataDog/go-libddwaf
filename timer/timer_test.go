// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v4/internal/unsafe"
	"github.com/DataDog/go-libddwaf/v4/timer"

	"github.com/stretchr/testify/require"
)

func hasExpired(t *testing.T, timer timer.Timer, duration time.Duration) {
	require.Greater(t, timer.Spent(), duration)
	require.Zero(t, timer.Remaining())
	require.True(t, timer.Exhausted())
}

func hasSumExpired(t *testing.T, timer timer.NodeTimer, duration time.Duration) {
	require.Greater(t, timer.SumSpent(), duration)
	require.Zero(t, timer.SumRemaining())
	require.True(t, timer.SumExhausted())
}

func TestBasic(t *testing.T) {
	t.Run("start-is-not-blank", func(t *testing.T) {
		newTimer, err := timer.NewTimer(timer.WithBudget(time.Second))
		require.NoError(t, err)
		require.NotEqual(t, time.Time{}, newTimer.Start())
	})

	t.Run("stop-means-stop", func(t *testing.T) {
		newTimer, err := timer.NewTimer(timer.WithBudget(time.Second))
		require.NoError(t, err)
		newTimer.Start()
		time.Sleep(1 * time.Millisecond)
		spent := newTimer.Stop()
		require.Equal(t, newTimer.Spent(), spent)

		// The timer was indeed stopped
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, newTimer.Spent(), spent)
	})

	t.Run("timed=spent", func(t *testing.T) {
		newTimer, err := timer.NewTimer(timer.WithBudget(time.Second))
		require.NoError(t, err)
		spent := newTimer.Timed(func(timer timer.Timer) {
			time.Sleep(1 * time.Millisecond)
		})

		require.GreaterOrEqual(t, newTimer.Spent(), time.Millisecond)
		require.Equal(t, newTimer.Spent(), spent)
	})

	t.Run("stop=spent", func(t *testing.T) {
		newTimer, err := timer.NewTimer(timer.WithBudget(time.Second))
		require.NoError(t, err)
		newTimer.Start()
		time.Sleep(1 * time.Millisecond)
		spent := newTimer.Stop()

		require.GreaterOrEqual(t, newTimer.Spent(), time.Millisecond)
		require.Equal(t, newTimer.Spent(), spent)
	})
}

func TestSum(t *testing.T) {

	t.Run("expired", func(t *testing.T) {
		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Millisecond), timer.WithComponents("a"))
		require.NoError(t, err)

		leafTimer := rootTimer.MustLeaf("a")
		leafTimer.Timed(func(timer timer.Timer) {
			time.Sleep(1 * time.Millisecond)
		})

		require.Greater(t, rootTimer.SumSpent(), time.Millisecond)
		require.Zero(t, rootTimer.SumRemaining())
		require.True(t, rootTimer.SumExhausted())
	})

	t.Run("remaining", func(t *testing.T) {
		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Hour), timer.WithComponents("a"))
		require.NoError(t, err)

		leafTimer := rootTimer.MustLeaf("a", timer.WithBudget(1*time.Millisecond))
		leafTimer.Timed(func(timer timer.Timer) {
			time.Sleep(1 * time.Millisecond)
		})

		require.GreaterOrEqual(t, rootTimer.SumSpent(), time.Millisecond)
		require.GreaterOrEqual(t, rootTimer.SumRemaining(), time.Duration(0))
		require.LessOrEqual(t, rootTimer.SumRemaining(), time.Hour-time.Millisecond)
		require.False(t, rootTimer.SumExhausted())
	})

	t.Run("multiple-components", func(t *testing.T) {
		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(4*time.Millisecond),
			timer.WithComponents("a"),
			timer.WithComponents("b"),
			timer.WithComponents("c"),
		)

		require.NoError(t, err)

		leafTimer := rootTimer.MustLeaf("a", timer.WithBudget(1*time.Millisecond))
		leafTimer.Timed(func(timer timer.Timer) {
			time.Sleep(1 * time.Millisecond)
		})

		require.True(t, leafTimer.Exhausted())

		leafTimer = rootTimer.MustLeaf("b", timer.WithBudget(1*time.Millisecond))
		leafTimer.Timed(func(timer timer.Timer) {
		})

		leafTimer = rootTimer.MustLeaf("c", timer.WithBudget(1*time.Millisecond))
		leafTimer.Timed(func(timer timer.Timer) {
			time.Sleep(1 * time.Millisecond)
		})

		require.True(t, leafTimer.Exhausted())

		require.GreaterOrEqual(t, rootTimer.SumSpent(), 2*time.Millisecond)
		require.GreaterOrEqual(t, rootTimer.SumRemaining(), time.Duration(0))
		require.False(t, rootTimer.SumExhausted())
	})
}

func TestFull(t *testing.T) {
	t.Run("leaf", func(t *testing.T) {
		t.Run("not-expired", func(t *testing.T) {
			newTimer, err := timer.NewTimer(timer.WithBudget(time.Second))
			require.NoError(t, err)
			newTimer.Timed(func(timer timer.Timer) {
				time.Sleep(1 * time.Millisecond)
			})

			require.GreaterOrEqual(t, newTimer.Spent(), time.Millisecond)
			require.GreaterOrEqual(t, newTimer.Remaining(), time.Duration(0))
			require.LessOrEqual(t, newTimer.Remaining(), time.Second)
			require.False(t, newTimer.Exhausted())
		})

		t.Run("expired", func(t *testing.T) {
			newTimer, err := timer.NewTimer(timer.WithBudget(time.Millisecond))
			require.NoError(t, err)
			newTimer.Timed(func(timer timer.Timer) {
				time.Sleep(1 * time.Millisecond)
			})

			hasExpired(t, newTimer, time.Millisecond)
		})
	})

	t.Run("root+leaf", func(t *testing.T) {
		t.Run("expired", func(t *testing.T) {
			rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Millisecond), timer.WithComponents("a"))
			require.NoError(t, err)

			leafTimer := rootTimer.MustLeaf("a")
			leafTimer.Timed(func(timer timer.Timer) {
				time.Sleep(1 * time.Millisecond)
			})

			hasExpired(t, leafTimer, time.Millisecond)
		})

		t.Run("not-expired", func(t *testing.T) {
			rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Second), timer.WithComponents("a"))
			require.NoError(t, err)

			leafTimer := rootTimer.MustLeaf("a")
			leafTimer.Timed(func(timer timer.Timer) {
				time.Sleep(1 * time.Millisecond)
			})

			require.GreaterOrEqual(t, leafTimer.Spent(), time.Millisecond)
			require.GreaterOrEqual(t, leafTimer.Remaining(), time.Duration(0))
			require.LessOrEqual(t, leafTimer.Remaining(), time.Second)
			require.False(t, leafTimer.Exhausted())

		})
	})
}

func TestInheritBudget(t *testing.T) {
	t.Run("root-leaf", func(t *testing.T) {
		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Millisecond), timer.WithComponents("a"))
		require.NoError(t, err)

		leafTimer := rootTimer.MustLeaf("a")
		leafTimer.Timed(func(timer timer.Timer) {
			time.Sleep(1 * time.Millisecond)
		})

		hasExpired(t, leafTimer, time.Millisecond)
		hasSumExpired(t, rootTimer, time.Millisecond)
	})

	t.Run("root-node-leaf", func(t *testing.T) {
		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Millisecond), timer.WithComponents("a"))
		require.NoError(t, err)

		nodeTimer, err := rootTimer.NewNode("a", timer.WithComponents("b"))
		require.NoError(t, err)

		leafTimer := nodeTimer.MustLeaf("b")
		leafTimer.Timed(func(timer timer.Timer) {
			time.Sleep(1 * time.Millisecond)
		})

		hasExpired(t, leafTimer, time.Millisecond)
		hasSumExpired(t, nodeTimer, time.Millisecond)
	})
}

func TestTree(t *testing.T) {
	t.Run("100-leafs", func(t *testing.T) {
		components := make([]timer.Key, 100)
		for i := range components {
			components[i] = timer.Key(strconv.Itoa(i))
		}

		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Hour), timer.WithComponents(components...))
		require.NoError(t, err)

		rootTimer.Start()

		var sum time.Duration
		for _, component := range components {
			leafTimer := rootTimer.MustLeaf(component)
			leafTimer.Timed(func(timer timer.Timer) {
			})

			sum += leafTimer.Spent()
			require.Equal(t, rootTimer.SumSpent(), sum)
		}

		rootTimer.Stop()
		require.GreaterOrEqual(t, rootTimer.Spent(), rootTimer.SumSpent())
	})

	t.Run("100-nodes-1-leaf", func(t *testing.T) {
		components := make([]timer.Key, 100)
		for i := range components {
			components[i] = timer.Key(strconv.Itoa(i))
		}

		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Hour), timer.WithComponents(components...))
		require.NoError(t, err)

		rootTimer.Start()

		var sum time.Duration
		for _, component := range components {
			nodeTimer, err := rootTimer.NewNode(component, timer.WithComponents("a"))
			require.NoError(t, err)

			leafTimer := nodeTimer.MustLeaf("a")
			_ = leafTimer.Timed(func(timer timer.Timer) {})

			sum += leafTimer.Spent()
			require.Equal(t, nodeTimer.SumSpent(), leafTimer.Spent())
		}

		rootTimer.Stop()
		require.GreaterOrEqual(t, rootTimer.Spent(), rootTimer.SumSpent())
	})

	t.Run("100-nodes-100-leaf", func(t *testing.T) {
		components := make([]timer.Key, 100)
		for i := range components {
			components[i] = timer.Key(strconv.Itoa(i))
		}

		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Hour), timer.WithComponents(components...))
		require.NoError(t, err)

		rootTimer.Start()

		var sum time.Duration
		for _, component := range components {
			nodeTimer, err := rootTimer.NewNode(component, timer.WithComponents(components...))
			require.NoError(t, err)

			nodeTimer.Start()

			var subSum time.Duration
			for _, component := range components {
				leafTimer := nodeTimer.MustLeaf(component)

				subSum += leafTimer.Timed(func(timer timer.Timer) {})
				require.Equal(t, subSum, nodeTimer.SumSpent())
			}

			sum += nodeTimer.Stop()
			require.Equal(t, sum, rootTimer.SumSpent())

			require.GreaterOrEqual(t, nodeTimer.Spent(), nodeTimer.SumSpent())
		}

		rootTimer.Stop()
	})

	t.Run("100-nodes-depth", func(t *testing.T) {
		rootTimer, err := timer.NewTreeTimer(timer.WithBudget(time.Hour), timer.WithComponents("a"))
		require.NoError(t, err)

		nodes := make([]timer.NodeTimer, 100)
		nodes[0] = rootTimer

		rootTimer.Start()
		defer rootTimer.Stop()

		for i := 1; i < 100; i++ {
			nodes[i], err = nodes[i-1].NewNode("a", timer.WithComponents("a"))
			require.NoError(t, err)
			nodes[i].Start()
			defer nodes[i].Stop()
		}

		for i := 1; i < 100; i++ {
			require.GreaterOrEqual(t, nodes[i-1].Spent(), nodes[i].Spent())
		}
	})
}

// Reproduce approximately the same number of calls that the WAF context will do
func BenchmarkContext(b *testing.B) {
	for i := 0; i < b.N; i++ {
		contextTimer, _ := timer.NewTreeTimer(
			timer.WithBudget(4*time.Millisecond),
			timer.WithComponents("Run"))

		// Let's say we do 4 calls to run in the WAF
		for i := 0; i < 4; i++ {
			runTimer, _ := contextTimer.NewNode("Run",
				timer.WithBudget(1*time.Millisecond),
				timer.WithComponents("persistent-encoder"),
				timer.WithComponents("ephemera-encoder"),
				timer.WithComponents("waiting"),
				timer.WithComponents("run"),
			)

			runTimer.Start()

			runTimer.MustLeaf("persistent-encoder").Timed(func(timer timer.Timer) {
				for i := 0; i < 10; i++ {
					unsafe.KeepAlive(timer.Exhausted())
				}
			})

			if contextTimer.SumExhausted() {
				// return
			}

			runTimer.MustLeaf("ephemera-encoder").Timed(func(timer timer.Timer) {
				for i := 0; i < 10; i++ {
					unsafe.KeepAlive(timer.Exhausted())
				}
			})

			if contextTimer.SumExhausted() {
				// return
			}

			runTimer.MustLeaf("waiting", timer.WithUnlimitedBudget()).Timed(func(timer timer.Timer) {
				// do some work
			})

			runTimer.MustLeaf("run").Timed(func(timer timer.Timer) {
				// do some work
			})

			runTimer.Stop()
		}
	}
}

// Reproduce approximately the same number of calls that the WAF run will do
func BenchmarkRun(b *testing.B) {
	for i := 0; i < b.N; i++ {
		runTimer, _ := timer.NewTreeTimer(timer.WithBudget(1*time.Millisecond),
			timer.WithComponents("persistent-encoder"),
			timer.WithComponents("ephemera-encoder"),
			timer.WithComponents("waiting"),
			timer.WithComponents("run"),
		)

		runTimer.Start()

		runTimer.MustLeaf("persistent-encoder").Timed(func(timer timer.Timer) {
			for i := 0; i < 10; i++ {
				unsafe.KeepAlive(timer.Exhausted())
			}
		})

		if runTimer.SumExhausted() {
			// return
		}

		runTimer.MustLeaf("ephemera-encoder").Timed(func(timer timer.Timer) {
			for i := 0; i < 10; i++ {
				unsafe.KeepAlive(timer.Exhausted())
			}
		})

		if runTimer.SumExhausted() {
			// return
		}

		runTimer.MustLeaf("waiting", timer.WithUnlimitedBudget()).Timed(func(timer timer.Timer) {
			// do some work
		})

		runTimer.MustLeaf("run").Timed(func(timer timer.Timer) {
			// do some work
		})

		runTimer.Stop()
	}
}
