// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package main

import (
	gotar "archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"

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
		if _, err = os.Stat(embedDir); errors.Is(err, os.ErrNotExist) {
			if err = os.MkdirAll(embedDir, 0755); err != nil {
				panic(err)
			}
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

	fmt.Println("All done! Don't forget to check in changes to include/ and internal/vendor/, check the libddwaf upgrade guide to update bindings!")
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

	var tar []byte
	{
		resp, err := http.Get(tarUrl)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		tar, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
	}

	var sha string
	{
		resp, err := http.Get(shaUrl)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		split := slices.Index(data, ' ')
		if split < 0 {
			panic("invalid sha256 file content")
		}
		sha = string(data[:split])
	}

	hash := sha256.Sum256(tar)
	sum := hex.EncodeToString(hash[:])

	if sum != sha {
		panic(fmt.Errorf("checksum mismatch on %s:\nExpected %s\nActual   %s", tarUrl, sha, sum))
	}

	reader, err := gzip.NewReader(bytes.NewReader(tar))
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

		var dest *os.File
		switch name := header.FileInfo().Name(); name {
		case "libddwaf.so", "libddwaf.dylib":
			destPath := path.Join(embedDir, name)
			fmt.Printf("... downloaded %s\n", destPath)
			{
				dest, err = os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
				if err != nil {
					panic(err)
				}
				defer dest.Close()
				_, err = io.Copy(dest, arch)
			}
			if err == nil {
				gosource := strings.Join(
					[]string{
						"// Unless explicitly stated otherwise all files in this repository are licensed",
						"// under the Apache License Version 2.0.",
						"// This product includes software developed at Datadog (https://www.datadoghq.com/).",
						"// Copyright 2016-present Datadog, Inc.",
						"",
						fmt.Sprintf("//go:build %s && %s && !go1.22", tgt.os, tgt.arch),
						"package vendor",
						"",
						`import _ "embed" // Needed for go:embed`,
						"",
						fmt.Sprintf("//go:embed %s-%s/%s", tgt.os, tgt.arch, name),
						"var libddwaf []byte",
						"",
						fmt.Sprintf(`const embedNamePattern = "libddwaf-*%s"`, path.Ext(name)),
						"", // Trailing new line...
					},
					"\n",
				)
				if err = os.WriteFile(path.Join(embedDir, "..", fmt.Sprintf("vendor_%s_%s.go", tgt.os, tgt.arch)), []byte(gosource), 0644); err != nil {
					panic(err)
				}
			}

			foundLib = true
		case "ddwaf.h":
			if tgt.primary {
				destPath := path.Join(rootDir, "include", name)
				fmt.Printf("... downloaded %s\n", destPath)
				dest, err = os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
				if err != nil {
					panic(err)
				}
				defer dest.Close()
				_, err = io.Copy(dest, arch)
			}
			foundHdr = true
		}
		if err != nil {
			panic(err)
		}
		if foundLib && foundHdr {
			break
		}
	}

	if !foundLib {
		panic(fmt.Errorf("could not find libddwaf.so/libddwaf.dylib in %s", tarUrl))
	}
	if !foundHdr {
		panic(fmt.Errorf("could not find ddwaf.h in %s", tarUrl))
	}
}

type target struct {
	os         string
	arch       string
	assetLabel string
	primary    bool // The one we'll get ddwaf.h from
}

var targets = []target{
	{
		os:         "darwin",
		arch:       "amd64",
		assetLabel: "darwin-x86_64",
	},
	{
		os:         "darwin",
		arch:       "arm64",
		assetLabel: "darwin-arm64",
	},
	{
		os:         "linux",
		arch:       "amd64",
		assetLabel: "x86_64-linux-musl",
		primary:    true,
	},
	{
		os:         "linux",
		arch:       "arm64",
		assetLabel: "aarch64-linux-musl",
	},
	{
		os:         "linux",
		arch:       "armv7",
		assetLabel: "armv7-linux-musl",
	},
	{
		os:         "linux",
		arch:       "i386",
		assetLabel: "i386-linux-musl",
	},
}

func init() {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Dir(filename)
	rootDir = path.Join(dir, "..", "..")
	libDir = path.Join(rootDir, "internal", "vendor")
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
