package waf

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func assertEqual(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestWebAppFirewall(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		url     string
		body    string
		res     string
		isError bool
	}{
		{
			name:   "Valid post request",
			method: "POST",
			url:    "/user/posts",
			body:   "hello",
		},
		{
			name:   "Valid get request",
			method: "GET",
			url:    "/user/posts",
		}, {
			name:   "Unvalid Delete request",
			method: "DELETE",
			url:    "/user/posts",
			res:    "unsupported HTTP method",
		}, {
			name:   "Unvalid url request",
			method: "GET",
			url:    "/user/pass",
			res:    "not allowed url",
		}, {
			name:   "SQL injection in POST",
			method: "POST",
			url:    "/user/posts",
			body:   "SELECT * FROM users",
			res:    "sql injection detected",
		}, {
			name:   "XSS injected request",
			method: "POST",
			url:    "/user/posts",
			body:   "<script>alert(\"hello\")</script>",
			res:    "xss injectin found",
		}, {
			name:   "Custom blocked patterns found",
			method: "POST",
			url:    "/user/posts",
			body:   "r/t78qw",
			res:    "custom pattern injectin found",
		},
	}
	wf, err := NewWaf("http://localhost:8090")
	if err != nil {
		t.Errorf("%v", err)
	}
	ts := httptest.NewServer(
		http.HandlerFunc(wf.WebAppFirewall),
	)
	defer ts.Close()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &bytes.Buffer{}
			b.WriteString(test.body)
			req, err := http.NewRequest(test.method, ts.URL+test.url, b)
			if err != nil {
				t.Errorf("%v", err)
			}
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("%v", err)
			}
			defer resp.Body.Close()
			if len(test.res) > 0 {
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Errorf("%v", err)
				}

				assertEqual(t, string(b), test.res)
			}

		})
	}
}

func TestParseIntoConfig(t *testing.T) {
	wf, err := NewWaf("http://localhost:8090")
	if err != nil {
		t.Errorf("%v", err)
	}
	assertEqual(t, wf.Cnf.AllowedHTTPMethods, []string{"GET", "POST"})
}
