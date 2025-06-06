// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package object

import (
	"fmt"
	"math"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/internal/pin"
	"github.com/DataDog/go-libddwaf/v4/timer"
)

type EncoderConfig struct {
	// Pinner is used to pin the data referenced by the encoded wafObjects.
	Pinner pin.Pinner
	// Timer makes sure the encoder doesn't spend too much time doing its job.
	Timer timer.Timer
	// MaxContainerSize is the maximum number of elements in a container (list, map, struct) that will be encoded.
	MaxContainerSize int
	// MaxStringLength is the maximum length of a string that will be encoded.
	MaxStringLength int
	// MaxContainerDepth is the maximum depth of the object that will be encoded.
	MaxContainerDepth int
}

// TruncationReason is a flag representing reasons why some input was not encoded in full.
type TruncationReason uint8

const (
	// StringLength indicates a string exceeded the maximum string length configured. The truncation
	// values indicate the actual length of truncated strings.
	StringLength TruncationReason = 1 << iota
	// ContainerSize indicates a container (list, map, struct) exceeded the maximum number of
	// elements configured. The truncation values indicate the actual number of elements in the
	// truncated container.
	ContainerSize
	// ContainerDepth indicates an overall object exceeded the maximum encoding depths configured. The
	// truncation values indicate an estimated actual depth of the truncated object. The value is
	// guaranteed to be less than or equal to the actual depth (it may not be more).
	ContainerDepth
)

func (reason TruncationReason) String() string {
	switch reason {
	case ContainerDepth:
		return "container_depth"
	case ContainerSize:
		return "container_size"
	case StringLength:
		return "string_length"
	default:
		return fmt.Sprintf("TruncationReason(%v)", int(reason))
	}
}

type Encoder interface {
	Encode(obj any) (*WAFObject, error)
	Truncations() map[TruncationReason][]int
}

// NewEncoder is a function that creates a new Encoder instance using the given config.
type NewEncoder func(cfg EncoderConfig) (Encoder, error)

// WAFObject is the C struct that represents a WAF object. It is passed as-is to the C-world.
// It is highly advised to use the methods on the object to manipulate it and not set the fields manually.
type WAFObject = bindings.WAFObject

// NewEncoderConfig creates a new EncoderConfig with the given pinner and timer using the default limits
func NewEncoderConfig(pinner pin.Pinner, timer timer.Timer) EncoderConfig {
	return EncoderConfig{
		Pinner:            pinner,
		Timer:             timer,
		MaxContainerSize:  bindings.MaxContainerSize,
		MaxStringLength:   bindings.MaxStringLength,
		MaxContainerDepth: bindings.MaxContainerDepth,
	}
}

// NewUnlimitedEncoderConfig creates a new EncoderConfig with the given pinner and unlimited encoding limits
func NewUnlimitedEncoderConfig(pinner pin.Pinner) EncoderConfig {
	timer, _ := timer.NewTimer(timer.WithUnlimitedBudget())
	return EncoderConfig{
		Pinner:            pinner,
		Timer:             timer,
		MaxContainerSize:  math.MaxInt,
		MaxStringLength:   math.MaxInt,
		MaxContainerDepth: math.MaxInt,
	}
}
