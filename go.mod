module github.com/DataDog/go-libddwaf/v2

go 1.19

require (
	github.com/ebitengine/purego v0.5.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4
	go.uber.org/atomic v1.11.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Version where import paths were not changed to go-libddwaf/v2
retract v2.0.0
