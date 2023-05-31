// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package waf

type encoder struct {
	arrayMaxSize   uint64
	stringMaxSize  uint64
	objectMaxDepth uint64
	allocator      allocator
}

func newMaxEncoder() *encoder {
	return &encoder{
		arrayMaxSize:   1<<63 - 1,
		stringMaxSize:  1<<63 - 1,
		objectMaxDepth: 1<<63 - 1,
	}
}

func (e encoder) Encode(data any) (*wafObject, error) {
	return nil, nil
}
