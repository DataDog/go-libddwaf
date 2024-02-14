#!/bin/sh -e

export DD_APPSEC_WAF_TIMEOUT=10m
export DD_APPSEC_WAF_LOG_FILTER="@ waf[.]cpp:"

# Read all go env and os variables as shell variables
# shellcheck disable=SC2046
eval $(go env)

case $GOVERSION in
    *1.20*|*1.19* )
        CGOCHECK="GODEBUG=cgocheck=2"
        ;;
    *)
        CGOCHECK="GOEXPERIMENT=cgocheck2"
esac

GOTESTSUM_COMMAND="go run gotest.tools/gotestsum@v1.11.0 -- -shuffle=on -v"

# Return true if the current OS is not Windows
WAF_ENABLED=$([ "$GOOS" = "windows" ] && echo false || echo true)

# run is tne main function that runs the tests
# It takes 2 arguments:
# - $1: whether the WAF is enabled or not (true or false)
# - $2: the tags to use for the tests (e.g. "appsec,cgo")
run() {
    waf_enabled="$1"
    tags="ci,$(echo "$2" | sed 's/cgo//')"
    nproc=$(nproc)
    test_tags="$2,$GOOS,$GOARCH"
    cgo=$(case "$2" in *"cgo"*) echo 1;; *) echo 0;; esac)

    echo "Running matrix "$test_tags" where the WAF is" "$($waf_enabled && echo "supported" || echo "not supported")" "..."
    env CGO_ENABLED=$cgo $GOTESTSUM_COMMAND -tags="$tags" -args -waf-build-tags="$test_tags" -waf-supported="$waf_enabled" ./...

    if $waf_enabled; then
        if [ "$cgo" = "1" ]; then
            echo "Running again with cgocheck enabled..."
            env "$CGOCHECK" CGO_ENABLED=1 $GOTESTSUM_COMMAND -tags="$tags" -args -waf-build-tags="$test_tags" -waf-supported="$waf_enabled" ./...
        fi

        echo "Running again $nproc times in parralel"
        env CGO_ENABLED=$cgo $GOTESTSUM_COMMAND -parallel $((nproc / 4)) -count="$nproc" -tags="$tags" -args -waf-build-tags="$test_tags" -waf-supported="$waf_enabled" ./...
    fi
}

run "$WAF_ENABLED" appsec                # WAF enabled (but not on windows)
run false                                # CGO Disabled
run false go1.23                         # Too recent go version (not tested)
run false go1.23,appsec                  # CGO disabled with appsec explicitely enabled but too recent go version
run false datadog.no_waf                 # WAF manually disabled
run false datadog.no_waf,appsec          # CGO disabled with appsec explicitely enabled but WAF manually disabled
run false datadog.no_waf,go1.23          # WAF manually disabled and go version to recent
run false datadog.no_waf,go1.23,appsec   # CGO disabled, WAF manually disabled, too recent go version with appsec explicitely enabled

# Check if we are running on Alpine and install the required dependencies for cgo
if [ -f /etc/os-release ] && grep -q Alpine < /etc/os-release; then
  apk add gcc musl-dev libc6-compat
fi

run "$WAF_ENABLED" cgo                   # WAF enabled (but not on windows)
run false go1.23,cgo                     # CGO disabled and too recent go version
run false datadog.no_waf,cgo             # WAF manually disabled and CGO disabled
run false datadog.no_waf,go1.23,cgo      # CGO disabled, WAF manually disabled, too recent go version
