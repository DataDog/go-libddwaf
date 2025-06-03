// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/go-github/v72/github"
	"github.com/iancoleman/orderedmap"
)

const (
	ghRepoOwner = "DataDog"
	ghRepoName  = "appsec-event-rules"
)

func main() {
	var output string
	flag.StringVar(&output, "output", "", "Path to the output file")
	flag.Parse()

	if output == "" {
		log.Fatalln("Missing required flag: -output")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatalln("GITHUB_TOKEN is not set; this is required to update the default ruleset!")
	}

	gh := github.NewClient(nil).WithAuthToken(token)

	ctx := context.Background()

	release, _, err := gh.Repositories.GetLatestRelease(ctx, ghRepoOwner, ghRepoName)
	if err != nil {
		log.Fatalln("Failed to get latest release:", err)
	}

	tag := release.GetTagName()
	log.Println("Latest release is", tag)

	file, _, err := gh.Repositories.DownloadContents(ctx, ghRepoOwner, ghRepoName, "build/recommended.json", &github.RepositoryContentGetOptions{Ref: tag})
	if err != nil {
		log.Fatalln("Failed to get recommended.json:", err)
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	dec.UseNumber()

	var ruleset orderedmap.OrderedMap
	if err := dec.Decode(&ruleset); err != nil {
		log.Fatalln("Failed to decode recommended.json:", err)
	}

	out, err := os.Create(output)
	if err != nil {
		log.Fatalln("Failed to create output file:", err)
	}
	defer out.Close()

	wr := io.WriteCloser(out)
	if strings.HasSuffix(output, ".gz") {
		var err error
		wr, err = gzip.NewWriterLevel(wr, gzip.BestCompression)
		if err != nil {
			log.Fatalln("Failed to create gzip writer:", err)
		}
		defer wr.Close()
	}

	enc := json.NewEncoder(wr)
	enc.SetIndent("", "")

	if err := enc.Encode(ruleset); err != nil {
		log.Fatalln("Failed to encode ruleset:", err)
	}
}
