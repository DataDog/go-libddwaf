// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"context"
	"errors"
	"fmt"
	"time"

	wafBindings "github.com/DataDog/go-libddwaf/v5/internal/bindings"
	"github.com/DataDog/go-libddwaf/v5/internal/pin"
	"github.com/DataDog/go-libddwaf/v5/timer"
	"github.com/DataDog/go-libddwaf/v5/waferrors"
)

// newRunTimer creates a run-scoped timer node from the parent timer.
// If key is empty, a standalone tree timer with the parent's remaining budget is created.
func newRunTimer(parent timer.NodeTimer, key timer.Key) (timer.NodeTimer, error) {
	if key == "" {
		return timer.NewTreeTimer(
			timer.WithComponents(
				EncodeTimeKey,
				DurationTimeKey,
				DecodeTimeKey,
			),
			timer.WithBudget(parent.SumRemaining()),
		)
	}

	return parent.NewNode(key,
		timer.WithComponents(
			EncodeTimeKey,
			DurationTimeKey,
			DecodeTimeKey,
		),
		timer.WithInheritedSumBudget(),
	)
}

// encodeAddressData encodes address data into WAF objects. Returns the encoded
// WAF object and any truncation info. The caller is responsible for merging
// truncations into its own truncation map.
func encodeAddressData(pinner pin.Pinner, addressData map[string]any, t timer.Timer) (*WAFObject, map[TruncationReason][]int, error) {
	if addressData == nil {
		return nil, nil, nil
	}

	encoder, err := newEncoder(newEncoderConfig(pinner, WithTimer(t)))
	if err != nil {
		return nil, nil, fmt.Errorf("could not create encoder: %w", err)
	}

	data, err := encoder.Encode(addressData)
	if err != nil && !errors.Is(err, waferrors.ErrTimeout) {
		return nil, nil, fmt.Errorf("failed to encode address data: %w", err)
	}

	if t.Exhausted() {
		return nil, nil, waferrors.ErrTimeout
	}

	return data, encoder.truncations, nil
}

// effectiveTimeoutMicros computes the WAF call timeout in microseconds,
// using the minimum of the run timer's remaining budget and ctx's deadline.
func effectiveTimeoutMicros(ctx context.Context, runTimer timer.NodeTimer) uint64 {
	timeoutDuration := runTimer.SumRemaining()
	if deadline, ok := ctx.Deadline(); ok {
		ctxRemaining := time.Until(deadline)
		if ctxRemaining < timeoutDuration || timeoutDuration == timer.UnlimitedBudget {
			timeoutDuration = ctxRemaining
		}
	}
	if timeoutDuration < 0 {
		timeoutDuration = 0
	}
	return uint64(timeoutDuration.Microseconds()) & 0x007FFFFFFFFFFFFF
}

// decodeWafResult decodes the WAF C result into a Go Result, tracking decode
// time and checking for timeout/context-cancellation.
func decodeWafResult(ctx context.Context, ret wafBindings.WAFReturnCode, result *WAFObject, runTimer timer.NodeTimer) (Result, error) {
	decodeTimer := runTimer.MustLeaf(DecodeTimeKey)
	decodeTimer.Start()
	defer decodeTimer.Stop()

	res, duration, err := unwrapWafResult(ret, result)
	runTimer.AddTime(DurationTimeKey, duration)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, ctxErr
	}
	if runTimer.SumExhausted() {
		return res, waferrors.ErrTimeout
	}
	return res, err
}
