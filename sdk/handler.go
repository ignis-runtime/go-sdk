package sdk

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"

	_ "github.com/ignis-runtime/go-sdk/sdk/http"
	"github.com/ignis-runtime/ignis-wasmtime/types"

	"google.golang.org/protobuf/proto"
)

type Response struct {
	Headers    http.Header
	Body       []byte
	StatusCode int
	Length     int
}

func NewFDResponse() *Response {
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    make(http.Header),
	}
}

func Handle(h http.Handler, stdin io.Reader) {
	// If no stdin provided, use os.Stdin as fallback
	if stdin == nil {
		stdin = os.Stdin
	}

	HandleWithIO(h, stdin, os.Stdout)
}

func HandleWithIO(h http.Handler, stdin io.Reader, stdout io.Writer) {
	b, err := io.ReadAll(stdin)
	if err != nil {
		log.Fatal(err)
	}
	w := NewFDResponse()

	var req types.FDRequest
	if err := proto.Unmarshal(b, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	r, err := http.NewRequest(req.Method, req.RequestUri, bytes.NewReader(req.Body))
	if err != nil {
		log.Fatal(err)
	}

	h.ServeHTTP(w, r) // execute the user's handler
	w.Length = len(w.Body)
	protoResp := types.FDResponse{
		Body:       w.Body,
		StatusCode: int32(w.StatusCode),
		Length:     int32(w.Length),
		Header:     make(map[string]*types.HeaderFields),
	}
	for k, v := range w.Headers {
		protoResp.Header[k] = &types.HeaderFields{Fields: v}
	}

	b, err = proto.Marshal(&protoResp)
	if err != nil {
		log.Printf("Error encoding response: %s", err)
	}

	// Write to provided stdout
	n, err := stdout.Write(b)
	if err != nil || n != len(b) {
		log.Printf("Error writing response: %s, bytes written: %d", err, n)
	}
}

func (w *Response) Header() http.Header {
	return w.Headers
}

func (w *Response) Write(b []byte) (n int, err error) {
	w.Body = append(w.Body, b...) // Store as []byte
	return len(b), nil
}

func (w *Response) WriteHeader(status int) {
	w.StatusCode = status
}

// HandleFunc provides a more direct way to handle requests in the WASI environment
// by working directly with the protobuf definitions, without the http.Handler adaptation layer.
func HandleFunc(handler func(*types.FDRequest) *types.FDResponse) {
	HandleFuncWithIO(handler, os.Stdin, os.Stdout)
}

// HandleFuncWithIO is similar to HandleFunc but allows specifying custom stdin and stdout.
func HandleFuncWithIO(handler func(*types.FDRequest) *types.FDResponse, stdin io.Reader, stdout io.Writer) {
	b, err := io.ReadAll(stdin)
	if err != nil {
		// Attempt to write an error response
		errorResp := &types.FDResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       []byte("failed to read request"),
		}
		b, _ = proto.Marshal(errorResp)
		stdout.Write(b)
		return
	}

	var req types.FDRequest
	if err := proto.Unmarshal(b, &req); err != nil {
		// Attempt to write an error response
		errorResp := &types.FDResponse{
			StatusCode: http.StatusBadRequest,
			Body:       []byte("failed to unmarshal request"),
		}
		b, _ = proto.Marshal(errorResp)
		stdout.Write(b)
		return
	}

	protoResp := handler(&req)

	b, err = proto.Marshal(protoResp)
	if err != nil {
		// Attempt to write an error response
		errorResp := &types.FDResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       []byte("failed to marshal response"),
		}
		b, _ = proto.Marshal(errorResp)
		stdout.Write(b)
		return
	}

	stdout.Write(b)
}

func init() {}
