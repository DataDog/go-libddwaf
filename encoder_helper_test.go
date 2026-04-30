// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/stretchr/testify/require"
)

func TestEncoderWriteString_NoTruncation(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	enc := Encoder{
		Config: EncoderConfig{
			Pinner:        &pinner,
			MaxStringSize: 64,
		},
	}

	var obj WAFObject
	enc.WriteString(&obj, "hello")

	require.True(t, enc.Truncations.IsEmpty(), "no truncation expected")
	require.True(t, obj.IsString())
}

func TestEncoderWriteString_TruncatesAndRecords(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	enc := Encoder{
		Config: EncoderConfig{
			Pinner:        &pinner,
			MaxStringSize: 4,
		},
	}

	var obj WAFObject
	enc.WriteString(&obj, "hello world")

	require.False(t, enc.Truncations.IsEmpty(), "truncation expected")
	require.Equal(t, []int{11}, enc.Truncations.StringTooLong)
	require.True(t, obj.IsString())
}

func TestEncoderWriteString_EmptyString(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	enc := Encoder{
		Config: EncoderConfig{
			Pinner:        &pinner,
			MaxStringSize: 64,
		},
	}

	var obj WAFObject
	enc.WriteString(&obj, "")

	require.True(t, enc.Truncations.IsEmpty(), "no truncation expected for empty string")
	require.True(t, obj.IsString())
}

func TestEncoderWriteLiteralString_NoTruncation(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	enc := Encoder{
		Config: EncoderConfig{
			Pinner:        &pinner,
			MaxStringSize: 64,
		},
	}

	var obj WAFObject
	enc.WriteLiteralString(&obj, "literal value")

	require.True(t, enc.Truncations.IsEmpty(), "no truncation expected")
	require.True(t, obj.IsString())
}

func TestEncoderTimeout_DelegatesToTimer(t *testing.T) {
	tmr, err := timer.NewTimer(timer.WithBudget(time.Nanosecond))
	require.NoError(t, err)
	tmr.Start()
	time.Sleep(2 * time.Millisecond)

	enc := Encoder{
		Config: EncoderConfig{
			Timer: tmr,
		},
	}

	require.True(t, enc.Timeout(), "timer should be exhausted")
}

func TestEncoderTruncationsAccumulate(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	enc := Encoder{
		Config: EncoderConfig{
			Pinner:        &pinner,
			MaxStringSize: 3,
		},
	}

	var obj1, obj2 WAFObject
	enc.WriteString(&obj1, "hello")
	enc.WriteString(&obj2, "world!")

	require.Equal(t, []int{5, 6}, enc.Truncations.StringTooLong)
}

func TestEncoderZeroValueUsable(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	enc := Encoder{}
	enc.Config.Pinner = &pinner
	enc.Config.MaxStringSize = 32

	var obj WAFObject
	enc.WriteString(&obj, "test")

	require.True(t, enc.Truncations.IsEmpty())
	require.True(t, obj.IsString())
}
