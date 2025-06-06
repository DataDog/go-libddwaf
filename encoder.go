// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package libddwaf

import (
	"github.com/DataDog/go-libddwaf/v4/object"
	"github.com/DataDog/go-libddwaf/v4/object/reflect"
)

// Deprecated: use [object.WAFObject] instead.
type WAFObject = object.WAFObject

// Deprecated: use [object.EncoderConfig] instead.
type EncoderConfig = object.EncoderConfig

// Deprecated: use [object.TruncationReason] instead.
type TruncationReason = object.TruncationReason

const (
	// Deprecated: use [object.StringLength] instead.
	StringTooLong = object.StringLength
	// Deprecated: use [object.ContainerSize] instead.
	ContainerTooLarge = object.ContainerSize
	// Deprecated: use [object.ContainerDepth] instead.
	ContainerTooDeep = object.ContainerDepth
)

const (
	// Deprecated: use [reflect.FieldTag] instead.
	AppsecFieldTag = reflect.FieldTag
	// Deprecated: use [reflect.IgnoreFieldTagValueIgnore] instead.
	AppsecFieldTagValueIgnore = reflect.IgnoreFieldTagValueIgnore
)

// Deprecated: use [reflect.Encodable] instead.
type Encodable = reflect.Encodable
