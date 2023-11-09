package waf

import (
	"encoding/json"
	"sort"
)

// Addresses type is a wrapper around a map connect the Run() function and the AddressesBuilder in a typesafe way
type Addresses map[string]any

// AddressesBuilder is a builder to build the addresses to be used by the WAF
// It is used to simplify all the user-retrieved day checks and to avoid the user to have to know the name of all
// addresses supported by the WAF and if the current ruleset really need them as input. The Flush() method returns
// the built addresses and the builder is ready to be used again.
type AddressesBuilder struct {
	// support comes from the current Handle and represent all the addresses that can be ingested by the ruleset
	support SupportedAddresses

	// addresses are the things built using the builder
	addresses Addresses
}

// Flush returns the built addresses
func (builder *AddressesBuilder) Flush() Addresses {
	oldAddresses := builder.addresses
	builder.addresses = make(Addresses)
	return oldAddresses
}

func (builder *AddressesBuilder) appendHttpAddress(addrName string, addrValue any) *AddressesBuilder {
	if !builder.support.isSupportedHttp(addrName) {
		return builder
	}

	builder.addresses[addrName] = addrValue
	return builder
}

func (builder *AddressesBuilder) appendGrpcAddress(addrName string, addrValue any) *AddressesBuilder {
	if !builder.support.isSupportedGrpc(addrName) {
		return builder
	}

	builder.addresses[addrName] = addrValue
	return builder
}

// HttpClientIP is the HTTP client IP address: http.client_ip
func (builder *AddressesBuilder) HttpClientIP(ip string) *AddressesBuilder {
	return builder.appendHttpAddress(clientIPAddr, ip)
}

// HttpUserID is the HTTP user ID: usr.id
func (builder *AddressesBuilder) HttpUserID(id string) *AddressesBuilder {
	return builder.appendHttpAddress(userIDAddr, id)
}

// RequestMethod is the HTTP request method: server.request.method
func (builder *AddressesBuilder) RequestMethod(verb string) *AddressesBuilder {
	return builder.appendHttpAddress(serverRequestMethodAddr, verb)
}

// RequestRawUri is the HTTP request raw URI: server.request.uri.raw
func (builder *AddressesBuilder) RequestRawUri(uri string) *AddressesBuilder {
	return builder.appendHttpAddress(serverRequestRawURIAddr, uri)
}

// RequestHeadersNoCookies are the HTTP request headers without the cookies: server.request.headers.no_cookies
func (builder *AddressesBuilder) RequestHeadersNoCookies(headers map[string][]string) *AddressesBuilder {
	if headers == nil || len(headers) == 0 {
		return builder
	}

	return builder.appendHttpAddress(serverRequestHeadersNoCookiesAddr, headers)
}

// RequestCookies are the HTTP request cookies: server.request.cookies
func (builder *AddressesBuilder) RequestCookies(cookies map[string][]string) *AddressesBuilder {
	if cookies == nil || len(cookies) == 0 {
		return builder
	}

	return builder.appendHttpAddress(serverRequestCookiesAddr, cookies)
}

// RequestQueryParams are the HTTP request query parameters: server.request.query
func (builder *AddressesBuilder) RequestQueryParams(queryParams map[string][]string) *AddressesBuilder {
	if queryParams == nil || len(queryParams) == 0 {
		return builder
	}

	return builder.appendHttpAddress(serverRequestQueryAddr, queryParams)
}

// RequestPathParams are the HTTP request path parameters: server.request.path_params
func (builder *AddressesBuilder) RequestPathParams(pathParams map[string]string) *AddressesBuilder {
	if pathParams == nil || len(pathParams) == 0 {
		return builder
	}

	return builder.appendHttpAddress(serverRequestPathParamsAddr, pathParams)
}

// RequestBody is the HTTP request body already parsed
func (builder *AddressesBuilder) RequestBody(body any) *AddressesBuilder {
	return builder.appendHttpAddress(serverRequestPathParamsAddr, body)
}

// RequestJsonBody is the HTTP request body parsed as JSON
func (builder *AddressesBuilder) RequestJsonBody(body []byte) (*AddressesBuilder, error) {
	if body == nil || len(body) == 0 {
		return builder, nil
	}

	var parsedBody any
	if err := json.Unmarshal(body, &parsedBody); err != nil {
		return builder, err
	}

	return builder.appendHttpAddress(serverRequestBodyAddr, parsedBody), nil
}

// ResponseStatus is the HTTP status code of the response
func (builder *AddressesBuilder) ResponseStatus(status int) *AddressesBuilder {
	return builder.appendHttpAddress(serverResponseStatusAddr, status)
}

// ResponseBody is the HTTP response body already parsed
func (builder *AddressesBuilder) ResponseBody(body any) *AddressesBuilder {
	return builder.appendHttpAddress(serverResponseBodyAddr, body)
}

// ResponseJsonBody is the HTTP response body parsed as JSON
func (builder *AddressesBuilder) ResponseJsonBody(body []byte) (*AddressesBuilder, error) {
	var parsedBody any
	if err := json.Unmarshal(body, &parsedBody); err != nil {
		return builder, err
	}

	return builder.appendHttpAddress(serverResponseBodyAddr, parsedBody), nil
}

// ResponseHeadersNoCookies are the HTTP response headers without the cookies
func (builder *AddressesBuilder) ResponseHeadersNoCookies(headers map[string][]string) *AddressesBuilder {
	if headers == nil || len(headers) == 0 {
		return builder
	}

	return builder.appendHttpAddress(serverResponseHeadersNoCookiesAddr, headers)
}

// ResponseCookies are the HTTP response cookies
func (builder *AddressesBuilder) ResponseCookies(cookies map[string][]string) *AddressesBuilder {
	if cookies == nil || len(cookies) == 0 {
		return builder
	}

	return builder.appendHttpAddress(serverResponseCookiesAddr, cookies)
}

// GrpcClientIP is the gRPC client IP
func (builder *AddressesBuilder) GrpcClientIP(ip string) *AddressesBuilder {
	return builder.appendGrpcAddress(clientIPAddr, ip)
}

// GrpcUserID is the gRPC user ID
func (builder *AddressesBuilder) GrpcUserID(id string) *AddressesBuilder {
	return builder.appendGrpcAddress(userIDAddr, id)
}

// GrpcRequestMessage is the gRPC request message
func (builder *AddressesBuilder) GrpcRequestMessage(message any) *AddressesBuilder {
	return builder.appendGrpcAddress(grpcServerRequestMessage, message)
}

// GrpcRequestMetadata is the gRPC request metadata
func (builder *AddressesBuilder) GrpcRequestMetadata(metadata map[string][]string) *AddressesBuilder {
	if metadata == nil || len(metadata) == 0 {
		return builder
	}

	return builder.appendGrpcAddress(grpcServerRequestMetadata, metadata)
}

// Persistent returns the addresses built by the builder as persistent addresses
func (builder *AddressesBuilder) Persistent() RunAddressData {
	return RunAddressData{
		Persistent: builder.Flush(),
	}
}

// Ephemeral returns the addresses built by the builder as ephemeral addresses
func (builder *AddressesBuilder) Ephemeral() RunAddressData {
	return RunAddressData{
		Ephemeral: builder.Flush(),
	}
}

// PersistantWithEphemeral returns the addresses built by the builder as persistent and ephemeral addresses
func PersistentWithEphemeral(persistent *AddressesBuilder, ephemeral *AddressesBuilder) RunAddressData {
	return RunAddressData{
		Persistent: persistent.Flush(),
		Ephemeral:  ephemeral.Flush(),
	}
}

type SupportedAddresses struct {
	http         map[string]struct{}
	grpc         map[string]struct{}
	notSupported map[string]struct{}
}

func newSupportedAddresses(addresses []string) (supportedAddresses SupportedAddresses) {
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

// IsEmptyHttp returns true if the HTTP addresses are empty
func (addresses SupportedAddresses) IsEmptyHttp() bool {
	return len(addresses.http) == 0
}

// IsEmptyGrpc returns true if the gRPC addresses are empty
func (addresses SupportedAddresses) IsEmptyGrpc() bool {
	return len(addresses.grpc) == 0
}

// IsEmpty returns true if the addresses are empty
func (addresses SupportedAddresses) IsEmpty() bool {
	return len(addresses.http) == 0 && len(addresses.grpc) == 0
}

// Partial supports returns true if some addresses are not supported
func (addresses SupportedAddresses) Partial() bool {
	return len(addresses.notSupported) > 0
}

// IsUserIdHttpSupported returns true if the HTTP user ID is supported by the current ruleset
func (addresses SupportedAddresses) IsUserIdHttpSupported() bool {
	return addresses.isSupportedHttp(userIDAddr)
}

// IsUserIdGrpcSupported returns true if the gRPC user ID is supported by the current ruleset
func (addresses SupportedAddresses) IsUserIdGrpcSupported() bool {
	return addresses.isSupportedGrpc(userIDAddr)
}

// IsClientIpHttpSupported returns true if the HTTP client IP is supported by the current ruleset
func (addresses SupportedAddresses) IsClientIpHttpSupported() bool {
	return addresses.isSupportedHttp(clientIPAddr)
}

// IsClientIpGrpcSupported returns true if the gRPC client IP is supported by the current ruleset
func (addresses SupportedAddresses) IsClientIpGrpcSupported() bool {
	return addresses.isSupportedGrpc(clientIPAddr)
}

// IsRequestMethodSupported returns true if the HTTP request method is supported by the current ruleset
func (addresses SupportedAddresses) IsRequestMethodSupported() bool {
	return addresses.isSupportedHttp(serverRequestMethodAddr)
}

// IsRequestRawUriSupported returns true if the HTTP request raw URI is supported by the current ruleset
func (addresses SupportedAddresses) IsRequestRawUriSupported() bool {
	return addresses.isSupportedHttp(serverRequestRawURIAddr)
}

// IsRequestHeadersNoCookiesSupported returns true if the HTTP request headers without the cookies is supported by the current ruleset
func (addresses SupportedAddresses) IsRequestHeadersNoCookiesSupported() bool {
	return addresses.isSupportedHttp(serverRequestHeadersNoCookiesAddr)
}

// IsRequestCookiesSupported returns true if the HTTP request cookies is supported by the current ruleset
func (addresses SupportedAddresses) IsRequestCookiesSupported() bool {
	return addresses.isSupportedHttp(serverRequestCookiesAddr)
}

// IsRequestQueryParamsSupported returns true if the HTTP request query parameters is supported by the current ruleset
func (addresses SupportedAddresses) IsRequestQueryParamsSupported() bool {
	return addresses.isSupportedHttp(serverRequestQueryAddr)
}

// IsRequestPathParamsSupported returns true if the HTTP request path parameters is supported by the current ruleset
func (addresses SupportedAddresses) IsRequestPathParamsSupported() bool {
	return addresses.isSupportedHttp(serverRequestPathParamsAddr)
}

// IsRequestBodySupported returns true if the HTTP request body is supported by the current ruleset
func (addresses SupportedAddresses) IsRequestBodySupported() bool {
	return addresses.isSupportedHttp(serverRequestBodyAddr)
}

// IsResponseStatusSupported returns true if the HTTP response status is supported by the current ruleset
func (addresses SupportedAddresses) IsResponseStatusSupported() bool {
	return addresses.isSupportedHttp(serverResponseStatusAddr)
}

// IsResponseBodySupported returns true if the HTTP response body is supported by the current ruleset
func (addresses SupportedAddresses) IsResponseBodySupported() bool {
	return addresses.isSupportedHttp(serverResponseBodyAddr)
}

// IsResponseHeadersNoCookiesSupported returns true if the HTTP response headers without the cookies is supported by the current ruleset
func (addresses SupportedAddresses) IsResponseHeadersNoCookiesSupported() bool {
	return addresses.isSupportedHttp(serverResponseHeadersNoCookiesAddr)
}

// IsResponseCookiesSupported returns true if the HTTP response cookies is supported by the current ruleset
func (addresses SupportedAddresses) IsResponseCookiesSupported() bool {
	return addresses.isSupportedHttp(serverResponseCookiesAddr)
}

// IsGrpcRequestMessageSupported returns true if the gRPC request message is supported by the current ruleset
func (addresses SupportedAddresses) IsGrpcRequestMessageSupported() bool {
	return addresses.isSupportedGrpc(grpcServerRequestMessage)
}

// IsGrpcRequestMetadataSupported returns true if the gRPC request metadata is supported by the current ruleset
func (addresses SupportedAddresses) IsGrpcRequestMetadataSupported() bool {
	return addresses.isSupportedGrpc(grpcServerRequestMetadata)
}

func (addresses SupportedAddresses) isSupported(addr string) bool {
	_, ok := addresses.notSupported[addr]
	return !ok
}

func (addresses SupportedAddresses) isSupportedHttp(addr string) bool {
	_, ok := addresses.http[addr]
	return ok
}

func (addresses SupportedAddresses) isSupportedGrpc(addr string) bool {
	_, ok := addresses.grpc[addr]
	return ok
}

// Common rule addresses currently supported by the WAF
const (
	clientIPAddr = "http.client_ip"
	userIDAddr   = "usr.id"
)

// HTTP rule addresses currently supported by the WAF
const (
	serverRequestMethodAddr            = "server.request.method"
	serverRequestRawURIAddr            = "server.request.uri.raw"
	serverRequestHeadersNoCookiesAddr  = "server.request.headers.no_cookies"
	serverRequestCookiesAddr           = "server.request.cookies"
	serverRequestQueryAddr             = "server.request.query"
	serverRequestPathParamsAddr        = "server.request.path_params"
	serverRequestBodyAddr              = "server.request.body"
	serverResponseStatusAddr           = "server.response.status"
	serverResponseBodyAddr             = "server.response.body"
	serverResponseHeadersNoCookiesAddr = "server.response.headers.no_cookies"
	serverResponseCookiesAddr          = "server.response.cookies"
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
	serverResponseBodyAddr,
	serverResponseHeadersNoCookiesAddr,
	serverResponseCookiesAddr,
	serverResponseStatusAddr,
	clientIPAddr,
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
	clientIPAddr,
	userIDAddr,
}

func init() {
	// sort the address lists to avoid mistakes and use sort.SearchStrings()
	sort.Strings(httpAddresses)
	sort.Strings(grpcAddresses)
}
