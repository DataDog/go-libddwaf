#!/bin/sh -ex

export DD_APPSEC_WAF_TIMEOUT=10m
export DD_APPSEC_WAF_LOG_FILTER="@ waf[.]cpp:"

GOVERSION="$(go env GOVERSION)"
GOOS="$(go env GOOS)"
GOARCH="$(go env GOARCH)"

contains() {
    case $1 in
        *$2*) echo true;;
        *) echo false;;
    esac
}

# Return true if the current OS is not Windows
WAF_ENABLED=$([ "$GOOS" = "windows" ] && echo false || echo true)

if $(contains "$GOVERSION" devel); then
    WAF_ENABLED=maybe
fi

# run is the main function that runs the tests
# It takes 2 arguments:
# - $1: whether the WAF is enabled or not (true or false)
# - $2: the tags to use for the tests (e.g. "appsec,cgo")
run() {
    waf_enabled="$1"
    tags="ci,$(echo "$2" | sed 's/cgo//')"
    nproc=$(getconf _NPROCESSORS_ONLN)
    test_tags="$2,$GOOS,$GOARCH"
    cgo=$($(contains "$2" cgo) && echo 1 || echo 0)

    echo "Running matrix $test_tags where the WAF is enablement is ${waf_enabled}..."
    env CGO_ENABLED="$cgo" go test -shuffle=on -tags="$tags" -args -waf-build-tags="$test_tags" -waf-supported="$waf_enabled" ./...

    if ! $waf_enabled; then
        return
    fi

    if [ "$cgo" = "1" ]; then
        echo "Running again with cgo options (cgocheck & race) enabled..."
        env "GOEXPERIMENT=cgocheck2" CGO_ENABLED=1 go test -race -shuffle=on -tags="$tags" -args -waf-build-tags="$test_tags" -waf-supported="$waf_enabled" ./...
    fi

    echo "Running again $nproc times in parralel"
    env CGO_ENABLED="$cgo" go test -shuffle=on -parallel $((nproc / 4 + 1)) -count="$nproc" -tags="$tags" -args -waf-build-tags="$test_tags" -waf-supported="$waf_enabled" ./...
}

run "$WAF_ENABLED" appsec                # WAF enabled (but not on windows)
run false                                # CGO Disabled
run false datadog.no_waf                 # WAF manually disabled
run false datadog.no_waf,appsec          # CGO disabled with appsec explicitely enabled but WAF manually disabled

# Check if we are running on Alpine and install the required dependencies for cgo
if [ -f /etc/os-release ] && grep -q Alpine < /etc/os-release; then
  apk add gcc musl-dev libc6-compat
fi

run "$WAF_ENABLED" cgo                   # WAF enabled (but not on windows)
run false datadog.no_waf,cgo             # WAF manually disabled and CGO enabled
