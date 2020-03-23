package api

import (
	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/user"

	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

const TestDBPath = ".test.db"

func testRouter(t *testing.T, us user.Service) *mux.Router {
	t.Helper()
	var secret = &auth.JWTSecret{}
	secret.SetSecret([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	r := auth.InitRBAC()

	sc := &ServerContext{Version: "69.420.80085", JWTSecret: secret, us: us, RBAC: r}

	router := router(sc)
	return router
}

// encodeBody is used to encode a request body
func encodeBody(t *testing.T, obj interface{}) io.Reader {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(obj); err != nil {
		t.Fatalf("error encoding obj: %#v", err)
	}
	return buf
}

func test(t *testing.T, name string, router *mux.Router, method string, uri string, r io.Reader, token string, expStatus int, expResp string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		req, err := http.NewRequest(method, uri, r)
		if err != nil {
			t.Fatal(err)
		}

		auth := fmt.Sprintf("Bearer %s", token)
		req.Header.Set("Authorization", auth)

		testRequest(t, router, req, expStatus, expResp)
	})
}

func testObj(t *testing.T, name string, router *mux.Router, method string, uri string, r io.Reader, token string, expStatus int, expObj interface{}) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		req, err := http.NewRequest(method, uri, r)
		if err != nil {
			t.Fatal(err)
		}

		auth := fmt.Sprintf("Bearer %s", token)
		req.Header.Set("Authorization", auth)

		testRequestObj(t, router, req, expStatus, expObj)
	})
}

func testNoAuth(t *testing.T, name string, router *mux.Router, method string, uri string, r io.Reader, expStatus int, expResp string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		req, err := http.NewRequest(method, uri, r)
		if err != nil {
			t.Fatal(err)
		}

		testRequest(t, router, req, expStatus, expResp)
	})
}

func testRequest(t *testing.T, router *mux.Router, req *http.Request, expectedStatus int, expected string) {
	t.Helper()
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if status := rr.Code; status != expectedStatus {
		t.Errorf("handler returned wrong status code:\n\tgot %v \n\twant %v",
			status, expectedStatus)
	}

	respBody := strings.TrimSuffix(rr.Body.String(), "\n")
	if respBody != expected {
		t.Errorf("handler returned unexpected body:\n\tgot %s \n\twant %s",
			respBody, expected)
	}
}

func testRequestObj(t *testing.T, router *mux.Router, req *http.Request, expectedStatus int, obj interface{}) {
	t.Helper()
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if status := rr.Code; status != expectedStatus {
		t.Errorf("handler returned wrong status code:\n\tgot %v \n\twant %v",
			status, expectedStatus)
	}

	s, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("Error marshaling: %#v", err)
	}
	expected := string(s)

	respBody := strings.TrimSuffix(rr.Body.String(), "\n")
	if respBody != expected {
		t.Errorf("handler returned unexpected body:\n\tgot %s \n\twant %s",
			respBody, expected)
	}
}
