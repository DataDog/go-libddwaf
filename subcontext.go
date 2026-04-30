// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

// Subcontext is a derived ephemeral evaluation scope. Spawned via Context.NewSubcontext.
//
// Transitional implementation: embeds *Context so existing methods
// (Run, Close, Truncations) are promoted. A later task replaces the embed
// with explicit fields and methods.
type Subcontext struct {
	*Context
}
