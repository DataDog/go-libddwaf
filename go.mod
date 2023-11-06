module github.com/DataDog/go-libddwaf

go 1.18

require (
	github.com/ebitengine/purego v0.5.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4
	go.uber.org/atomic v1.11.0
	golang.org/x/sys v0.13.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract v1.6.0 // Breaking version, published too soon
