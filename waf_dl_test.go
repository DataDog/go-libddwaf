// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ((darwin && (amd64 || arm64)) || (linux && (amd64 || arm64)) || (windows && (amd64 || 386))) && !go1.22

package waf

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/DataDog/go-libddwaf/internal/vendor"
	"github.com/stretchr/testify/require"
)

func TestVerifyHeader(t *testing.T) {
	switch runtime.GOOS {
	case "darwin":
		testVerifyMachOHeader(t)
	case "linux":
		testVerifyELFHeader(t)
	case "windows":
		testVerifyPEHeader(t)
	default:
		panic(fmt.Sprintf("unexpected GOOS=%s", runtime.GOOS))
	}
}

func TestEnsureRequiredArch(t *testing.T) {
	val := os.Getenv("GOARCH_ASSERT")
	if val != "" {
		require.Equal(t, val, runtime.GOARCH)
	}
}

// testVerifyELFHeader is here to ease the debug cases that will likely need
// to dive in the linker to debug because the error handling is very poor
func testVerifyELFHeader(t *testing.T) {
	file, err := vendor.DumpEmbeddedWAF()
	require.NoError(t, err)

	defer func() {
		_ = os.Remove(file)
	}()

	elfFile, err := elf.Open(file)
	require.NoError(t, err)

	switch runtime.GOARCH {
	case "amd64":
		require.Equal(t, elf.EM_X86_64, elfFile.Machine, "Wrong architecture")
	case "arm64":
		require.Equal(t, elf.EM_AARCH64, elfFile.Machine, "Wrong architecture")
	default:
		panic(fmt.Sprintf("unexpected GOARCH=%s", runtime.GOARCH))
	}

	require.Equal(t, elf.ET_DYN, elfFile.Type, "Is not a shared library")

	//TODO(eliott.bouhana) add more checks
}

// testVerifyMachOHeader is here to ease the debug cases that will likely need
// to dive in the linker to debug because the error handling is very poor
func testVerifyMachOHeader(t *testing.T) {
	file, err := vendor.DumpEmbeddedWAF()
	require.NoError(t, err)

	defer func() {
		_ = os.Remove(file)
	}()

	machOFile, err := macho.Open(file)
	require.NoError(t, err)

	switch runtime.GOARCH {
	case "amd64":
		require.Equal(t, macho.CpuAmd64, machOFile.Cpu, "Wrong architecture")
	case "arm64":
		require.Equal(t, macho.CpuArm64, machOFile.Cpu, "Wrong architecture")
	default:
		panic(fmt.Sprintf("unexpected GOARCH=%s", runtime.GOARCH))
	}

	require.Equal(t, macho.TypeDylib, machOFile.Type, "Is not a shared library")

	//TODO(eliott.bouhana) add more checks
}

// testVerifyPEHeader is here to ease the debug cases that will likely need to
// dive in the linker to debug because the error handling is very poor
func testVerifyPEHeader(t *testing.T) {
	file, err := vendor.DumpEmbeddedWAF()
	require.NoError(t, err)

	defer func() { _ = os.Remove(file) }()

	peFile, err := pe.Open(file)
	require.NoError(t, err)

	switch runtime.GOARCH {
	case "amd64":
		require.Equal(t, uint16(pe.IMAGE_FILE_MACHINE_AMD64), peFile.Machine, "Wrong architecture")
	case "386":
		require.Equal(t, uint16(pe.IMAGE_FILE_MACHINE_I386), peFile.Machine, "Wrong architecture")
	default:
		panic(fmt.Sprintf("unexpected GOARCH=%s", runtime.GOARCH))
	}
}
