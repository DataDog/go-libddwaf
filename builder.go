// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
)

// Builder manages an evolving WAF configuration over time. Its lifecycle is
// typically tied to that of a remote configuration client, as its purpose is to
// keep an up-to-date view of the current coniguration with low overhead. This
// type is not safe for concurrent use, and users should protect it with a mutex
// or similar when sharing it across multiple goroutines. All methods of this
// type are safe to call with a nil receiver.
type Builder struct {
	handle bindings.WAFBuilder
}

// NewBuilder creates a new [Builder] instance. Its lifecycle is typically tied
// to that of a remote configuration client, as its purpose is to keep an
// up-to-date view of the current coniguration with low overhead. Returns nil if
// an error occurs when initializing the builder. The caller is responsible for
// calling [Builder.Close] when the builder is no longer needed.
func NewBuilder(keyObfuscatorRegex string, valueObfuscatorRegex string) (*Builder, error) {
	if ok, err := Load(); !ok {
		return nil, err
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()
	hdl := wafLib.BuilderInit(newConfig(&pinner, keyObfuscatorRegex, valueObfuscatorRegex))

	if hdl == 0 {
		return nil, errors.New("failed to initialize the WAF builder")
	}

	return &Builder{handle: hdl}, nil
}

// Close releases all resources associated with this builder.
func (b *Builder) Close() {
	if b == nil || b.handle == 0 {
		return
	}
	wafLib.BuilderDestroy(b.handle)
	b.handle = 0
}

var (
	errUpdateFailed  = errors.New("failed to update WAF Builder instance")
	errBuilderClosed = errors.New("builder has already been closed")
)

// AddOrUpdateConfig adds or updates a configuration fragment to this [Builder].
// Returns the [Diagnostics] produced by adding or updating this configuration.
func (b *Builder) AddOrUpdateConfig(path string, fragment any) (Diagnostics, error) {
	if b == nil || b.handle == 0 {
		return Diagnostics{}, errBuilderClosed
	}

	if path == "" {
		return Diagnostics{}, errors.New("path cannot be blank")
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	encoder, err := newDefaultEncoder(newMaxEncoderConfig(&pinner))
	if err != nil {
		return Diagnostics{}, fmt.Errorf("could not create encoder: %w", err)
	}

	frag, err := encoder.Encode(fragment)
	if err != nil {
		return Diagnostics{}, fmt.Errorf("could not encode the config fragment into a WAF object; %w", err)
	}

	var diagnosticsWafObj bindings.WAFObject
	defer wafLib.ObjectFree(&diagnosticsWafObj)

	res := wafLib.BuilderAddOrUpdateConfig(b.handle, path, frag, &diagnosticsWafObj)

	var diags Diagnostics
	if !diagnosticsWafObj.IsInvalid() {
		// The Diagnostics object will be invalid if the config was completely
		// rejected.
		diags, err = decodeDiagnostics(&diagnosticsWafObj)
		if err != nil {
			return diags, fmt.Errorf("failed to decode WAF diagnostics: %w", err)
		}
	}

	if !res {
		return diags, errUpdateFailed
	}
	return diags, nil
}

// RemoveConfig removes the configuration associated with the given path from
// this [Builder]. Returns true if the removal was successful.
func (b *Builder) RemoveConfig(path string) bool {
	if b == nil || b.handle == 0 {
		return false
	}

	return wafLib.BuilderRemoveConfig(b.handle, path)
}

// ConfigPaths returns the list of currently loaded configuration paths.
func (b *Builder) ConfigPaths(filter string) []string {
	if b == nil || b.handle == 0 {
		return nil
	}

	return wafLib.BuilderGetConfigPaths(b.handle, filter)
}

// Build creates a new [Handle] instance that uses the current configuration.
// Returns nil if an error occurs when building the handle. The caller is
// responsible for calling [Handle.Close] when the handle is no longer needed.
// This function may return nil.
func (b *Builder) Build() *Handle {
	if b == nil || b.handle == 0 {
		return nil
	}

	hdl := wafLib.BuilderBuildInstance(b.handle)
	if hdl == 0 {
		return nil
	}

	return wrapHandle(hdl)
}
