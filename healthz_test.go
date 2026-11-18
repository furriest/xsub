package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// /healthz отвечает без пароля только с loopback: на нём держится HEALTHCHECK
// Docker. С любого другого адреса — та же Basic-авторизация, что и везде.
func TestHealthz(t *testing.T) {
	a := newTestApp(t)
	h := a.handler()

	do := func(remote, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8099"+path, nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	for _, remote := range []string{"127.0.0.1:40000", "[::1]:40000"} {
		w := do(remote, "/healthz")
		if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "ok" {
			t.Fatalf("%s /healthz: %d %q", remote, w.Code, w.Body.String())
		}
	}
	// Остальное с loopback по-прежнему под паролем.
	if w := do("127.0.0.1:40000", "/"); w.Code != http.StatusUnauthorized {
		t.Fatalf("/ без пароля: %d", w.Code)
	}
	// Из домашней сети /healthz без пароля не открывается.
	if w := do("192.168.1.10:40000", "/healthz"); w.Code != http.StatusUnauthorized {
		t.Fatalf("/healthz из LAN без пароля: %d", w.Code)
	}
}
