package waf

import (
	"github.com/ebitengine/purego"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func getLibddwafBench(b *testing.B) uintptr {
	file, err := os.CreateTemp("", "libddwaf-*.so")
	require.NoError(b, err)

	defer os.Remove(file.Name())

	err = os.WriteFile(file.Name(), libddwaf, 0400)
	require.NoError(b, err)

	lib, err := purego.Dlopen(file.Name(), purego.RTLD_GLOBAL|purego.RTLD_NOW)
	require.NoError(b, err)

	return lib
}

func getSymbolBench(b *testing.B, lib uintptr, symbol string) uintptr {
	sym, err := purego.Dlsym(lib, symbol)
	require.NoError(b, err)
	return sym
}
