package main

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"regexp"
	"slices"
)

func main() {
	log.Println("Listing all available Go versions using `go list -m -versions go`...")
	cmd := exec.Command("go", "list", "-m", "-versions", "-json=Versions", "go")
	cmd.Env = append(os.Environ(), "GOPROXY=https://proxy.golang.org")
	out, err := cmd.Output()
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Parsing output of `go list -m -versions go`...")
	var module struct {
		Versions []string `json:"Versions"`
	}
	if err := json.Unmarshal(out, &module); err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			log.Println("STDERR:", string(err.Stderr))
		}
		log.Fatalln(err)
	}

	if len(module.Versions) == 0 {
		log.Fatalln("No versions found!")
	}

	// Versions are returned sorted in ascending SemVer order.
	slices.Reverse(module.Versions)

	log.Println("Looking for a release candidate version...")
	goVersions := make([]string, 2, 3)
	goVersions[0] = "oldstable"
	goVersions[1] = "stable"

	// Versions are represented in a form that isn't quite regular SemVer.
	versionRe := regexp.MustCompile(`^(1\.\d+)(\.\d+)?(?:(beta|rc)(\d+))?$`)
	for _, v := range module.Versions {
		parts := versionRe.FindStringSubmatch(v)
		if parts == nil {
			log.Fatalln("Encountered unsupported version string:", v)
		}
		major, minor, pre, serial := parts[1], parts[2], parts[3], parts[4]
		if pre == "" {
			// Not a pre-release version, there is no "next" release available.
			log.Println("No relevant release candidate version found!")
			break
		}
		if pre != "rc" {
			// Not a release candidate; we don't test against those.
			continue
		}
		// †he minor is omitted when it's ".0"; but actions/setup-go needs it.
		if minor == "" {
			minor = ".0"
		}
		rcVersion := major + minor + "-" + pre + "." + serial
		log.Println("Found release candidate version:", rcVersion)
		goVersions = append(goVersions, rcVersion)
		// We have what we came here for, we can break out of the loop now.
		break
	}

	log.Println("Encoding output as a JSON array...")
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(goVersions); err != nil {
		log.Fatalln(err)
	}

	log.Println("Done!")
}
