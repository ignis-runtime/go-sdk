package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unsafe"
)

// HostRequest is the structure sent from the guest to the host.
type HostRequest struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"`
}

// HostResponse is the structure sent from the host back to the guest.
type HostResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	Body       []byte      `json:"body"`
}

//go:wasmimport env host_http_request
func _host_http_request(reqPtr, reqLen, respPtr, respLen uint32) (ret uint32)

// WasiRoundTripper implements the http.RoundTripper interface.
type WasiRoundTripper struct{}

// RoundTrip is the core of the transport. It's called for each HTTP request.
func (t *WasiRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Read the request body, if any.
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close() // Close the original body
	}

	// Create the request structure to be serialized to JSON.
	hostReq := HostRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: req.Header,
		Body:    body,
	}

	// Marshal the request to JSON.
	reqBytes, err := json.Marshal(hostReq)
	if err != nil {
		return nil, err
	}

	// Allocate a buffer for the host's JSON response.
	respBuf := make([]byte, 32768) // 32KB buffer
	respPtr, respLen := &respBuf[0], uint32(len(respBuf))

	// Pass the JSON request to the host.
	reqPtr, reqLen := &reqBytes[0], uint32(len(reqBytes))
	ret := _host_http_request(uint32(uintptr(unsafe.Pointer(reqPtr))), reqLen, uint32(uintptr(unsafe.Pointer(respPtr))), respLen)

	if ret == 0 {
		return nil, errors.New("host http request failed")
	}

	// Unmarshal the host's JSON response.
	var hostResp HostResponse
	if err := json.Unmarshal(respBuf[:ret], &hostResp); err != nil {
		return nil, err
	}

	// Reconstruct the *http.Response.
	return &http.Response{
		StatusCode: hostResp.StatusCode,
		Header:     hostResp.Headers,
		Body:       io.NopCloser(bytes.NewReader(hostResp.Body)),
		Request:    req,
	}, nil
}

// SetWasiHTTPTransport sets up the custom WASI transport for HTTP requests.
func SetWasiHTTPTransport() {
	// Create a single instance of the transport
	wasiTransport := &WasiRoundTripper{}

	// 1. Overwrite the DefaultTransport.
	// This ensures that any new client created like `client := &http.Client{}`
	// (which usually defaults to nil Transport) will now use this transport.
	http.DefaultTransport = wasiTransport

	// 2. Overwrite the DefaultClient's transport.
	// This covers calls like http.Get(), http.Post(), etc.
	http.DefaultClient.Transport = wasiTransport
}

// init replaces the default HTTP transport with our custom WASI transport.
func init() {
	SetWasiHTTPTransport()
}
