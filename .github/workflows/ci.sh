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

    # COVERAGE is set by the CI on a single matrix entry to avoid duplicate uploads.
    cover=""
    if [ "${COVERAGE:-}" = "true" ] && [ "$2" = "appsec" ]; then
        cover="-coverprofile=coverage.out"
    fi

    echo "Running matrix $test_tags where the WAF is enablement is ${waf_enabled}..."
    env CGO_ENABLED="$cgo" go test $cover -shuffle=on -tags="$tags" -args -waf-build-tags="$test_tags" -waf-supported="$waf_enabled" ./...

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

# Only the matrix entry that set COVERAGE=true produces coverage.out, so this uploads once.
# datadog-ci reads either DATADOG_API_KEY or DD_API_KEY; both are absent on fork pull
# requests, where the upload is skipped instead of failing the job.
if [ "${COVERAGE:-}" = "true" ] && [ -f coverage.out ]; then
    if [ -z "${DATADOG_API_KEY:-}" ] && [ -z "${DD_API_KEY:-}" ]; then
        echo "No Datadog API key (DATADOG_API_KEY/DD_API_KEY) is set; skipping coverage upload"
    else
        DD_SERVICE=go-libddwaf npx --yes @datadog/datadog-ci coverage upload coverage.out
    fi
fi
