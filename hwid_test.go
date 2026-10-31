package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const hwidTestNode = `[{"remarks":"NL","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"` + tUUID + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}]}]`

// HWID отправляется, только если без него панель не выдала узлов, и он постоянный.
func TestFetchSubHWIDOnlyWhenNeeded(t *testing.T) {
	needHWID := false
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("X-Hwid"))
		if r.Header.Get("User-Agent") != "Happ/4.8.2" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		if needHWID && r.Header.Get("X-Hwid") == "" {
			w.Write([]byte("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp#stub"))
			return
		}
		w.Write([]byte(hwidTestNode))
	}))
	defer srv.Close()
	hwidMu.Lock()
	hwidCache = ""
	hwidMu.Unlock()
	c := &Config{dir: t.TempDir()}
	a := &App{c: c}
	s := Subscription{Name: "t", URL: srv.URL}

	// Панель пускает без HWID — он не отправляется и даже не создаётся.
	if _, _, n, _, _, err := a.fetchSub(context.Background(), s, "Happ/4.8.2", nil, false); err != nil || len(n) != 1 {
		t.Fatalf("без HWID: %v, узлов %d", err, len(n))
	}
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("лишний HWID: %q", got)
	}
	if _, err := os.Stat(c.path("hwid")); err == nil {
		t.Fatal("файл hwid создан без надобности")
	}

	// Панель требует HWID — второй запрос с ним, значение постоянное.
	needHWID, got = true, nil
	for i := 0; i < 2; i++ {
		if _, _, n, _, _, err := a.fetchSub(context.Background(), s, "Happ/4.8.2", nil, false); err != nil || len(n) != 1 {
			t.Fatalf("с HWID: %v, узлов %d", err, len(n))
		}
	}
	if len(got) != 4 || got[0] != "" || len(got[1]) != 32 || got[1] != got[3] {
		t.Fatalf("запросы: %q", got)
	}
}
