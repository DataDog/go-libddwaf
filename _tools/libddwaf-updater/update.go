// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package main

import (
	gotar "archive/tar"
	"compress/gzip"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"

	"github.com/bitfield/script"
	"github.com/google/go-github/v56/github"
)

var (
	rootDir        string
	libDir         string
	versionFile    string
	currentVersion string
)

func main() {
	force := os.Args[1] == "--force"

	gh := github.NewClient(nil)

	release, _, err := gh.Repositories.GetLatestRelease(context.Background(), "DataDog", "libddwaf")
	if err != nil {
		panic(err)
	}

	version := *release.TagName
	if version == currentVersion {
		fmt.Printf("Already up-to-date with v%s\n", version)
		if force {
			fmt.Println("--force is set, re-downloading assets anyway!")
		} else {
			return
		}
	} else {
		fmt.Printf("Will upgrade from v%s to v%s\n", currentVersion, version)
	}

	assets := make(map[string]*github.ReleaseAsset, len(release.Assets))
	for _, asset := range release.Assets {
		if asset.Name == nil {
			continue
		}
		assets[*asset.Name] = asset
	}

	wg := sync.WaitGroup{}
	wg.Add(len(targets))
	for _, tgt := range targets {
		embedDir := path.Join(libDir, fmt.Sprintf("%s-%s", tgt.os, tgt.arch))
		created := false
		if _, err = os.Stat(embedDir); errors.Is(err, os.ErrNotExist) {
			if err = os.MkdirAll(embedDir, 0755); err != nil {
				panic(err)
			}
			created = true
		}
		if created || force {
			if err := os.WriteFile(path.Join(embedDir, "vendor.go"), []byte(vendorMarkerFile), 0644); err != nil {
				panic(err)
			}
			createEmbedSource(tgt)
		}
		go handleTarget(&wg, version, tgt, embedDir, assets)
	}

	wg.Wait()

	file, err := os.OpenFile(versionFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	written := 0
	for written < len(version) {
		wrote, err := file.WriteString(version[written:])
		if err != nil {
			panic(err)
		}
		written += wrote
	}

	fmt.Println("All done! Don't forget to check in changes to include/ and internal/lib/, check the libddwaf upgrade guide to update bindings!")
}

func createEmbedSource(tgt target) {
	gosource := strings.Join(
		[]string{
			"// Unless explicitly stated otherwise all files in this repository are licensed",
			"// under the Apache License Version 2.0.",
			"// This product includes software developed at Datadog (https://www.datadoghq.com/).",
			"// Copyright 2016-present Datadog, Inc.",
			"",
			fmt.Sprintf("//go:build %s && %s && !go1.22", tgt.os, tgt.arch),
			"package lib",
			"",
			`import _ "embed" // Needed for go:embed`,
			"",
			fmt.Sprintf("//go:embed %s-%s/%s.%s", tgt.os, tgt.arch, tgt.base, tgt.ext),
			"var libddwaf []byte",
			"",
			fmt.Sprintf(`const embedNamePattern = "%s-*.%s"`, tgt.base, tgt.ext),
			"", // Trailing new line...
		},
		"\n",
	)
	if err := os.WriteFile(path.Join(libDir, fmt.Sprintf("lib_%s_%s.go", tgt.os, tgt.arch)), []byte(gosource), 0644); err != nil {
		panic(err)
	}
}

func handleTarget(wg *sync.WaitGroup, version string, tgt target, embedDir string, assets map[string]*github.ReleaseAsset) {
	defer wg.Done()

	tarName := fmt.Sprintf("libddwaf-%s-%s.tar.gz", version, tgt.assetLabel)
	shaName := fmt.Sprintf("%s.sha256", tarName)

	tarAsset, found := assets[tarName]
	if !found {
		panic(fmt.Errorf("could not find tarball named %s", tarName))
	}
	shaAsset, found := assets[shaName]
	if !found {
		panic(fmt.Errorf("could not find sha256 named %s", shaName))
	}

	tarUrl := *tarAsset.BrowserDownloadURL
	shaUrl := *shaAsset.BrowserDownloadURL

	tmpdir, err := os.MkdirTemp("", "libddwaf-updater-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpdir)

	if _, err := script.Get(tarUrl).WriteFile(path.Join(tmpdir, tarName)); err != nil {
		panic(err)
	}
	sha, err := script.Get(shaUrl).String()
	if err != nil {
		panic(err)
	}
	sha = sha[:64] // Only keep the hex-encoded SHA256
	sum, err := script.File(path.Join(tmpdir, tarName)).SHA256Sum()
	if err != nil {
		panic(err)
	}
	if sum != sha {
		panic(fmt.Errorf("checksum mismatch on %s:\nExpected %s\nActual   %s", tarUrl, sha, sum))
	}

	file, err := os.Open(path.Join(tmpdir, tarName))
	if err != nil {
		panic(err)
	}
	reader, err := gzip.NewReader(file)
	if err != nil {
		panic(err)
	}
	arch := gotar.NewReader(reader)
	foundLib := false
	foundHdr := false
	for {
		header, err := arch.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			panic(err)
		}

		var destPath string
		switch name := header.FileInfo().Name(); name {
		case "libddwaf.so", "libddwaf.dylib", "ddwaf.dll":
			destPath = path.Join(embedDir, name)
			foundLib = true
		case "ddwaf.h":
			if tgt.primary {
				destPath = path.Join(rootDir, "include", name)
				foundHdr = true
			} else {
				continue
			}
		default:
			continue
		}

		fmt.Printf("... downloaded %s\n", destPath)
		if _, err := script.NewPipe().WithReader(arch).WriteFile(destPath); err != nil {
			panic(err)
		}
		if path.Ext(destPath) != ".h" {
			// Make the libraries executable, as this can be useful to link directly to those objects to perform troubleshooting.
			if err := os.Chmod(destPath, 0755); err != nil {
				panic(err)
			}
		}

		if foundLib && (foundHdr || !tgt.primary) {
			break
		}
	}

	if !foundLib {
		panic(fmt.Errorf("could not find libddwaf.so/libddwaf.dylib in %s", tarUrl))
	}
	if tgt.primary && !foundHdr {
		panic(fmt.Errorf("could not find ddwaf.h in %s", tarUrl))
	}
}

type target struct {
	os         string
	arch       string
	base       string // The base name (without extension)
	ext        string // The file extension
	assetLabel string
	primary    bool // The one we'll get ddwaf.h from
}

var targets = []target{
	{
		os:         "darwin",
		arch:       "amd64",
		base:       "libddwaf",
		ext:        "dylib",
		assetLabel: "darwin-x86_64",
	},
	{
		os:         "darwin",
		arch:       "arm64",
		base:       "libddwaf",
		ext:        "dylib",
		assetLabel: "darwin-arm64",
	},
	{
		os:         "linux",
		arch:       "amd64",
		base:       "libddwaf",
		ext:        "so",
		assetLabel: "x86_64-linux-musl",
		primary:    true,
	},
	{
		os:         "linux",
		base:       "libddwaf",
		ext:        "so",
		arch:       "arm64",
		assetLabel: "aarch64-linux-musl",
	},
	{
		os:         "windows",
		arch:       "amd64",
		base:       "ddwaf",
		ext:        "dll",
		assetLabel: "windows-x64",
	},
	{
		os:         "windows",
		arch:       "386",
		base:       "ddwaf",
		ext:        "dll",
		assetLabel: "windows-win32",
	},
	//// These are currently not supported by ebitengine/purego:
	// {os: "linux", arch: "armv7", ext: "so", assetLabel: "armv7-linux-musl"},
	// {os: "linux", arch: "i386", ext: "so", assetLabel: "i386-linux-musl"},
}

const vendorMarkerFile = `// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package vendor

// This file is there to make sure "go mod vendor" does not drop those directories, as it otherwise removes
// any directiory that contains no ".go" files.
`

func init() {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Dir(filename)
	rootDir = path.Join(dir, "..", "..")
	libDir = path.Join(rootDir, "internal", "lib")
	versionFile = path.Join(libDir, ".version")

	file, err := os.Open(versionFile)
	if errors.Is(err, os.ErrNotExist) {
		currentVersion = "<none>"
		return
	}
	if err != nil {
		panic(err)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}

	currentVersion = string(data)
}
