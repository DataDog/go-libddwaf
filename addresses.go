package waf

import (
	"encoding/json"
	"sort"
)

// HTTP rule addresses currently supported by the WAF
const (
	serverRequestMethodAddr           = "server.request.method"
	serverRequestRawURIAddr           = "server.request.uri.raw"
	serverRequestHeadersNoCookiesAddr = "server.request.headers.no_cookies"
	serverRequestCookiesAddr          = "server.request.cookies"
	serverRequestQueryAddr            = "server.request.query"
	serverRequestPathParamsAddr       = "server.request.path_params"
	serverRequestBodyAddr             = "server.request.body"
	serverResponseStatusAddr          = "server.response.status"
	httpClientIPAddr                  = "http.client_ip"
	userIDAddr                        = "usr.id"
)

// List of HTTP rule addresses currently supported by the WAF
var httpAddresses = []string{
	serverRequestMethodAddr,
	serverRequestRawURIAddr,
	serverRequestHeadersNoCookiesAddr,
	serverRequestCookiesAddr,
	serverRequestQueryAddr,
	serverRequestPathParamsAddr,
	serverRequestBodyAddr,
	serverResponseStatusAddr,
	httpClientIPAddr,
	userIDAddr,
}

// gRPC rule addresses currently supported by the WAF
const (
	grpcServerRequestMessage  = "grpc.server.request.message"
	grpcServerRequestMetadata = "grpc.server.request.metadata"
)

// List of gRPC rule addresses currently supported by the WAF
var grpcAddresses = []string{
	grpcServerRequestMessage,
	grpcServerRequestMetadata,
	httpClientIPAddr,
	userIDAddr,
}

func init() {
	// sort the address lists to avoid mistakes and use sort.SearchStrings()
	sort.Strings(httpAddresses)
	sort.Strings(grpcAddresses)
}

// Addresses type is a wrapper around a map connect the Run() function and the AddressesBuilder in a typesafe way
type Addresses map[string]any

type supportedAddresses struct {
	http         map[string]struct{}
	grpc         map[string]struct{}
	notSupported map[string]struct{}
}

func newSupportedAddresses(addresses []string) (supportedAddresses supportedAddresses) {
	// Filter the supported addresses only
	for _, addr := range addresses {
		supported := false
		if i := sort.SearchStrings(httpAddresses, addr); i < len(httpAddresses) && httpAddresses[i] == addr {
			supportedAddresses.http[addr] = struct{}{}
			supported = true
		}
		if i := sort.SearchStrings(grpcAddresses, addr); i < len(grpcAddresses) && grpcAddresses[i] == addr {
			supportedAddresses.grpc[addr] = struct{}{}
			supported = true
		}

		if !supported {
			supportedAddresses.notSupported[addr] = struct{}{}
		}
	}

	return
}

func (addrs supportedAddresses) isSupported(addr string) bool {
	_, ok := addrs.notSupported[addr]
	return !ok
}

func (addrs supportedAddresses) isSupportedHttp(addr string) bool {
	_, ok := addrs.http[addr]
	return ok
}

func (addrs supportedAddresses) isSupportedGrpc(addr string) bool {
	_, ok := addrs.grpc[addr]
	return ok
}

type AddressesBuilder struct {
	// support comes from the current Handle and represent all the addresses that can be ingested by the ruleset
	support supportedAddresses

	// addresses are the things built using the builder
	addresses Addresses
}

func NewAddressesBuilder(handle *Handle) *AddressesBuilder {
	return &AddressesBuilder{
		support:   handle.addresses,
		addresses: make(Addresses),
	}
}

func (builder *AddressesBuilder) appendHttpAddress(addrName string, addrValue any) {
	if !builder.support.isSupportedHttp(addrName) {
		return
	}

	builder.addresses[addrName] = addrValue
}

func (builder *AddressesBuilder) HttpClientIP(ip string) *AddressesBuilder {
	builder.appendHttpAddress(httpClientIPAddr, ip)
	return builder
}

func (builder *AddressesBuilder) Method(verb string) *AddressesBuilder {
	builder.appendHttpAddress(serverRequestMethodAddr, verb)
	return builder
}

func (builder *AddressesBuilder) RawUri(uri string) *AddressesBuilder {
	builder.appendHttpAddress(serverRequestRawURIAddr, uri)
	return builder
}

func (builder *AddressesBuilder) RequestHeadersNoCookies(headers map[string][]string) *AddressesBuilder {
	if headers == nil {
		return builder
	}

	builder.appendHttpAddress(serverRequestHeadersNoCookiesAddr, headers)
	return builder
}

func (builder *AddressesBuilder) RequestCookies(cookies map[string][]string) *AddressesBuilder {
	if cookies == nil {
		return builder
	}

	builder.appendHttpAddress(serverRequestCookiesAddr, cookies)
	return builder
}

func (builder *AddressesBuilder) RequestQueryParams(queryParams map[string][]string) *AddressesBuilder {
	if queryParams == nil {
		return builder
	}

	builder.appendHttpAddress(serverRequestQueryAddr, queryParams)
	return builder
}

func (builder *AddressesBuilder) RequestPathParams(pathParams map[string]string) *AddressesBuilder {
	if pathParams == nil {
		return builder
	}

	builder.appendHttpAddress(serverRequestPathParamsAddr, pathParams)
	return builder
}

func (builder *AddressesBuilder) RequestBody(body any) *AddressesBuilder {
	builder.appendHttpAddress(serverRequestPathParamsAddr, body)
	return builder
}

func (builder *AddressesBuilder) RequestJsonBody(body []byte) (*AddressesBuilder, error) {
	parsedBody := make(map[string]any)
	if err := json.Unmarshal(body, &parsedBody); err != nil {
		return builder, err
	}

	builder.appendHttpAddress(serverRequestBodyAddr, parsedBody)
	return builder, nil
}
