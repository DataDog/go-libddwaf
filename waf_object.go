// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"github.com/DataDog/go-libddwaf/v5/internal/bindings"
)

// WAFObject is a 16-byte value type matching the C ddwaf_object union.
// It can be constructed as a zero value (which is invalid by default)
// and mutated in place via Set* methods.
type WAFObject = bindings.WAFObject

// WAFObjectKV is a key-value pair used in v2 maps.
// Its zero value is two invalid WAFObjects.
type WAFObjectKV = bindings.WAFObjectKV

// WAFObjectType is the type discriminator for a WAFObject.
type WAFObjectType = bindings.WAFObjectType

// Type constants for WAFObject.
const (
	WAFInvalidType       WAFObjectType = bindings.WAFInvalidType
	WAFNilType           WAFObjectType = bindings.WAFNilType
	WAFBoolType          WAFObjectType = bindings.WAFBoolType
	WAFIntType           WAFObjectType = bindings.WAFIntType
	WAFUintType          WAFObjectType = bindings.WAFUintType
	WAFFloatType         WAFObjectType = bindings.WAFFloatType
	WAFStringType        WAFObjectType = bindings.WAFStringType
	WAFLiteralStringType WAFObjectType = bindings.WAFLiteralStringType
	WAFSmallStringType   WAFObjectType = bindings.WAFSmallStringType
	WAFArrayType         WAFObjectType = bindings.WAFArrayType
	WAFMapType           WAFObjectType = bindings.WAFMapType
	// WAFLargeArrayType is an array that uses the large layout of libddwaf
	// 2.1.0 and later: its size and capacity are 28-bit values. libddwaf
	// selects this layout when the capacity is more than math.MaxUint16, so a
	// large array can have fewer items than that, or none. Go writes this
	// layout too: [WAFObject.SetArrayData] and the [Encoder] builders use it
	// for a capacity of more than 65,535 items.
	WAFLargeArrayType WAFObjectType = bindings.WAFLargeArrayType
	// WAFLargeMapType is a map that uses the large layout of libddwaf 2.1.0
	// and later: its size and capacity are 28-bit values. libddwaf selects
	// this layout when the capacity is more than math.MaxUint16, so a large
	// map can have fewer entries than that, or none. Go writes this layout
	// too: [WAFObject.SetMapData] and the [Encoder] builders use it for a
	// capacity of more than 65,535 entries.
	WAFLargeMapType WAFObjectType = bindings.WAFLargeMapType
)
