// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// moduleMajorVersionRegexp extracts the major version suffix (e.g. "5" for
// ".../go-libddwaf/v5") from the module directive in go.mod.
var moduleMajorVersionRegexp = regexp.MustCompile(`(?m)^module\s+\S+/v(\d+)\s*$`)

// cgoExportRegexp matches a `//export <symbol>` CGO directive.
var cgoExportRegexp = regexp.MustCompile(`^//export\s+(\S+)`)

// currentModuleMajorVersion reads go.mod at the repository root and returns
// its major version suffix, e.g. "V5" for module github.com/DataDog/go-libddwaf/v5.
func currentModuleMajorVersion(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("failed to read go.mod: %v", err)
	}

	matches := moduleMajorVersionRegexp.FindSubmatch(data)
	if matches == nil {
		t.Fatalf("could not find a versioned module directive (.../vN) in go.mod")
	}

	return "V" + string(matches[1])
}

// TestCgoExportedSymbolsAreVersioned ensures that every CGO `//export`-ed
// symbol in this module ends with "V<N>", where N is the module's current
// major version (as declared in go.mod).
//
// Context: this repository uses Go's semantic import versioning, so major
// version bumps change the module's import path (e.g. .../v4 -> .../v5),
// but CGO-exported symbols have process-wide C linkage and are NOT
// namespaced by the Go import path. If two major versions of this module
// (e.g. v4 and v5) both get linked into the same binary -- which happens
// whenever a dependent module hasn't finished migrating off the old major
// version yet -- and both export a symbol with the *same* name, the link
// step fails with "multiple definition of '<symbol>'".
//
// This has already happened twice before (see commits fixing conflicts
// between v2/v3, and v3/v4) because the exported symbol name was not
// updated when the module's major version was bumped. This test exists to
// catch that class of regression automatically on every future major bump.
func TestCgoExportedSymbolsAreVersioned(t *testing.T) {
	majorVersion := currentModuleMajorVersion(t)

	var checked int
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".omc", ".omo", ".opencode", ".sisyphus", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			m := cgoExportRegexp.FindStringSubmatch(line)
			if m == nil {
				continue
			}

			checked++
			symbol := m[1]
			if !strings.HasSuffix(symbol, majorVersion) {
				t.Errorf(
					"%s: CGO-exported symbol %q does not end with the current module major version %q; "+
						"rename it so it stays unique when this module and another major version of it "+
						"are linked into the same binary (see e.g. multiple-definition link errors caused "+
						"by unversioned exported symbols in past major bumps)",
					path, symbol, majorVersion,
				)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk repository for CGO exported symbols: %v", err)
	}

	if checked == 0 {
		t.Fatalf("expected to find at least one //export directive in the repository, found none; " +
			"update this test if the exported log callback was removed or relocated")
	}
}
