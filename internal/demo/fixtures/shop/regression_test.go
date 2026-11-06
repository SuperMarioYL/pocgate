package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIndexServes pins the page the operator relies on. It passes before and
// after a correct patch; a patch that breaks it breaks the closure conjunction.
func TestIndexServes(t *testing.T) {
	rec := httptest.NewRecorder()
	index(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "shop fixture") {
		t.Fatalf("/ returned %d %q", rec.Code, rec.Body.String())
	}
}
