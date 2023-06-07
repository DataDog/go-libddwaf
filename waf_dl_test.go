// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Purego only works on linux/macOS with amd64 and arm64 from now
//go:build (linux || darwin) && (amd64 || arm64)

package waf

import (
	"os"
	"runtime"
	"testing"

	"debug/elf"
	"debug/macho"

	"github.com/stretchr/testify/require"
)

// TestVerifyELFHeader is here to ease the debug cases that will likely need
// to dive in the linker to debug because the error handling is very poor
func TestVerifyELFHeader(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF Test is for linux")
	}

	file, err := dumpWafLibrary()
	require.NoError(t, err)

	defer func() {
		file.Close()
		os.Remove(file.Name())
	}()

	elfFile, err := elf.Open(file.Name())
	require.NoError(t, err)

	switch runtime.GOARCH {
	case "amd64":
		require.Equal(t, elf.EM_X86_64, elfFile.Machine, "Wrong architecture")
	case "arm64":
		require.Equal(t, elf.EM_AARCH64, elfFile.Machine, "Wrong architecture")
	}

	require.Equal(t, elf.ET_DYN, elfFile.Type, "Is not a shared library")

	//TODO(eliott.bouhana) add more checks
}

// TestVerifyMachOHeader is here to ease the debug cases that will likely need
// to dive in the linker to debug because the error handling is very poor
func TestVerifyMachOHeader(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Mach-O Test is for darwin")
	}

	file, err := dumpWafLibrary()
	require.NoError(t, err)

	defer func() {
		file.Close()
		os.Remove(file.Name())
	}()

	machOFile, err := macho.Open(file.Name())
	require.NoError(t, err)

	switch runtime.GOARCH {
	case "amd64":
		require.Equal(t, macho.CpuAmd64, machOFile.Cpu, "Wrong architecture")
	case "arm64":
		require.Equal(t, macho.CpuArm64, machOFile.Cpu, "Wrong architecture")
	}

	require.Equal(t, macho.TypeDylib, machOFile.Type, "Is not a shared library")

	//TODO(eliott.bouhana) add more checks
}
