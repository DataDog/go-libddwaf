// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	emptyfree "github.com/DataDog/go-libddwaf/internal/empty-free"
	"go.uber.org/atomic"
)

// Handle represents an instance of the WAF for a given ruleset.
type Handle struct {
	cHandle        wafHandle
	mutex          sync.RWMutex
	contextCounter *atomic.Uint32
	rulesetInfo    RulesetInfo
}

// NewHandle takes rules and the obfuscator config and return a new WAF to work with. The order of action is the following:
// - Open the WAF library libddwaf.so using dlopen
// - Encode the rule free form object as a ddwaf_object so send them to the WAF
// - Create a ddwaf_config object and fill the values
// - Run ddwaf_init to get a handle from the waf
// - Check for errors and streamline the ddwaf_ruleset_info returned
func NewHandle(rules any, keyObfuscatorRegex string, valueObfuscatorRegex string) (*Handle, error) {

	if err := InitWaf(); err != nil {
		return nil, err
	}

	if reflect.ValueOf(rules).Type() == reflect.TypeOf([]byte(nil)) {
		return nil, errors.New("cannot encode byte array as top-level rules object")
	}

	encoder := newMaxEncoder()
	obj, err := encoder.Encode(rules)
	if err != nil {
		return nil, fmt.Errorf("could not encode the WAF ruleset into a WAF object: %w", err)
	}

	defer encoder.allocator.KeepAlive()

	config := newConfig(&encoder.allocator, keyObfuscatorRegex, valueObfuscatorRegex)
	cRulesetInfo := new(wafRulesetInfo)

	cHandle := wafLib.wafInit(obj, config, cRulesetInfo)
	if cHandle == 0 {
		return nil, errors.New("could not instanciate the WAF")
	}

	defer wafLib.wafRulesetInfoFree(cRulesetInfo)

	errorsMap, err := decodeErrors(&cRulesetInfo.errors)
	if err != nil { // Something is very wrong
		return nil, fmt.Errorf("could not decode the WAF ruleset errors: %w", err)
	}

	return &Handle{
		cHandle:        cHandle,
		contextCounter: atomic.NewUint32(1), // We count the handle itself in the counter
		rulesetInfo: RulesetInfo{
			Loaded:  cRulesetInfo.loaded,
			Failed:  cRulesetInfo.failed,
			Errors:  errorsMap,
			Version: gostring(cRulesetInfo.version),
		},
	}, nil
}

// NewContext a new WAF context and increase the number of references to the WAF
// handle. A nil value is returned when the WAF handle can no longer be used
// or the WAF context couldn't be created.
func (handle *Handle) NewContext() *Context {
	// Handle has been released
	if handle.contextCounter.Load() == 0 {
		return nil
	}

	cContext := wafLib.wafContextInit(handle.cHandle)
	if cContext == 0 {
		return nil
	}

	handle.contextCounter.Inc()
	return &Context{handle: handle, cContext: cContext}
}

// RulesetInfo returns the rules initialization metrics for the current WAF handle
func (handle *Handle) RulesetInfo() RulesetInfo {
	return handle.rulesetInfo
}

// Addresses returns the list of addresses the WAF rule is expecting.
func (handle *Handle) Addresses() []string {
	return wafLib.wafRequiredAddresses(handle.cHandle)
}

// CloseContext call ddwaf_context_destroy and eventually ddwaf_destroy on the handle
func (handle *Handle) CloseContext(context *Context) {
	wafLib.wafContextDestroy(context.cContext)
	if handle.contextCounter.Dec() == 0 {
		wafLib.wafDestroy(handle.cHandle)
	}
}

// Close put the handle in termination state, when all the contexts are close the handle will be destroyed
func (handle *Handle) Close() {
	// There is still Contexts that are not closed
	if handle.contextCounter.Dec() > 0 {
		return
	}

	wafLib.wafDestroy(handle.cHandle)
}

func newConfig(allocator *allocator, keyObfuscatorRegex string, valueObfuscatorRegex string) *wafConfig {
	config := new(wafConfig)
	*config = wafConfig{
		limits: wafConfigLimits{
			maxContainerDepth: wafMaxContainerDepth,
			maxContainerSize:  wafMaxContainerSize,
			maxStringLength:   wafMaxStringLength,
		},
		obfuscator: wafConfigObfuscator{
			keyRegex:   allocator.AllocRawString(keyObfuscatorRegex),
			valueRegex: allocator.AllocRawString(valueObfuscatorRegex),
		},
		freeFn: emptyfree.EmptyFreeFn,
	}
	return config
}

func goRunError(rc wafReturnCode) error {
	switch rc {
	case wafErrInternal:
		return ErrInternal
	case wafErrInvalidObject:
		return ErrInvalidObject
	case wafErrInvalidArgument:
		return ErrInvalidArgument
	default:
		return fmt.Errorf("unknown waf return code %d", int(rc))
	}
}
