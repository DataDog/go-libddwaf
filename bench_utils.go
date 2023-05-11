package waf

import (
	"github.com/ebitengine/purego"
	"os"
)

func getLibddwaf() uintptr {
	file, err := os.CreateTemp("", "libddwaf-*.so")
	if err != nil {
		panic(err)
	}

	defer os.Remove(file.Name())

	err = os.WriteFile(file.Name(), libddwaf, 0400)
	if err != nil {
		panic(err)
	}

	lib, err := purego.Dlopen(file.Name(), purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		panic(err)
	}

	return lib
}

func getSymbol(lib uintptr, symbol string) uintptr {
	sym, err := purego.Dlsym(lib, symbol)
	if err != nil {
		panic(err)
	}
	return sym
}
