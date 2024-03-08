// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package timer

import (
	"time"
)

// UnlimitedBudget is a special value for the budget that means the timer has no budget
var UnlimitedBudget = ^time.Duration(0) - 1

// InheritedBudget is a special value for the budget that means the timer should inherit the budget from its parent
// It is the default value if no options such as WithBudget, WithUnlimitedBudget or WithInheritedBudget are provided
var InheritedBudget = time.Duration(0)

// Config is the configuration of a timer. It can be created through the use of options
type Config struct {
	// Components store all the components of the timer
	Components []string
	// Budget is the time budget for the timer
	Budget time.Duration
}

func newConfig(options ...Option) Config {
	config := Config{}
	for _, option := range options {
		option(&config)
	}
	return config
}

// Option are the configuration options for any type of timer. Please read the documentation of said timer to see which options are available
type Option func(*Config)

// WithBudget is an Option that sets the Budget value
func WithBudget(budget time.Duration) Option {
	return func(c *Config) {
		c.Budget = budget
	}
}

// WithUnlimitedBudget is an Option that sets the UnlimitedBudget flag on Config.Budget
func WithUnlimitedBudget() Option {
	return func(c *Config) {
		c.Budget = UnlimitedBudget
	}
}

// WithInheritedBudget is an Option that sets the InheritedBudget flag on Config.Budget
func WithInheritedBudget() Option {
	return func(c *Config) {
		c.Budget = InheritedBudget
	}
}

// WithComponents is an Option that adds multiple components to the Components list
func WithComponents(components ...string) Option {
	return func(c *Config) {
		c.Components = append(c.Components, components...)
	}
}
