package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
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

func TestFetchSubForceHWID(t *testing.T) {
	var ids []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Hwid")
		ids = append(ids, id)
		if id == "" {
			w.WriteHeader(444)
			return
		}
		_, _ = w.Write([]byte(hwidTestNode))
	}))
	defer srv.Close()
	hwidMu.Lock()
	hwidCache = ""
	hwidMu.Unlock()
	t.Cleanup(func() { hwidMu.Lock(); hwidCache = ""; hwidMu.Unlock() })
	c := &Config{dir: t.TempDir()}
	a := &App{c: c}
	s := Subscription{Name: "test", URL: srv.URL, ForceHWID: true}
	for i := 0; i < 2; i++ {
		_, _, nodes, _, used, err := a.fetchSub(context.Background(), s, "Happ/4.8.2", nil, false)
		if err != nil || len(nodes) != 1 || !used {
			t.Fatalf("forced HWID: err=%v nodes=%d used=%v", err, len(nodes), used)
		}
	}
	if len(ids) != 2 || len(ids[0]) != 32 || ids[0] != ids[1] {
		t.Fatal("HWID должен присутствовать в первом запросе и оставаться постоянным")
	}
	stored, err := os.ReadFile(c.path("hwid"))
	if err != nil || string(stored) != ids[0]+"\n" {
		t.Fatal("HWID не сохранён для последующих запусков")
	}
}

func TestSubscriptionForceHWIDCompatibility(t *testing.T) {
	var old Subscription
	if err := json.Unmarshal([]byte(`{"name":"old","url":"https://example.com/sub"}`), &old); err != nil || old.ForceHWID {
		t.Fatalf("старая подписка: err=%v force_hwid=%v", err, old.ForceHWID)
	}
	c := &Config{dir: t.TempDir()}
	want := []Subscription{{Name: "test", URL: "https://example.com/sub", ForceHWID: true}}
	if err := saveSubsFile(c, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadSubs(c)
	if err != nil || len(got) != 1 || !got[0].ForceHWID {
		t.Fatalf("настройка не сохранилась: %v", err)
	}
}

func TestFetchSubForceHWIDRequiresPersistentID(t *testing.T) {
	hwidMu.Lock()
	hwidCache, hwidWriteErr = "", nil
	hwidMu.Unlock()
	t.Cleanup(func() { hwidMu.Lock(); hwidCache, hwidWriteErr = "", nil; hwidMu.Unlock() })
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++ }))
	defer srv.Close()
	c := &Config{dir: filepath.Join(t.TempDir(), "missing")}
	a := &App{c: c}
	s := Subscription{URL: srv.URL, ForceHWID: true}
	for i := 0; i < 2; i++ {
		if _, _, _, _, _, err := a.fetchSub(context.Background(), s, "Happ", nil, false); err == nil {
			t.Fatal("должна возвращаться ошибка сохранения HWID")
		}
	}
	if requests != 0 {
		t.Fatal("запрос не должен отправляться с несохранённым HWID")
	}
}

func TestFetchSubForceHWIDViaVPN(t *testing.T) {
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(444) }))
	defer panel.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			result <- err
			return
		}
		if _, err = conn.Write([]byte{5, 0}); err != nil {
			result <- err
			return
		}
		request := make([]byte, 4)
		if _, err = io.ReadFull(conn, request); err != nil {
			result <- err
			return
		}
		if request[3] != 1 {
			result <- fmt.Errorf("unexpected address type %d", request[3])
			return
		}
		if _, err = io.ReadFull(conn, make([]byte, 6)); err != nil {
			result <- err
			return
		}
		if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			result <- err
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			result <- err
			return
		}
		if req.Header.Get("X-Hwid") == "" {
			result <- fmt.Errorf("HWID отсутствует в запросе через VPN")
			return
		}
		_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(hwidTestNode), hwidTestNode)
		result <- err
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	probePort, _ := strconv.Atoi(port)
	c := &Config{dir: t.TempDir()}
	c.Xray.ProbePort = probePort
	a := &App{c: c}
	_, _, nodes, _, _, err := a.fetchSub(context.Background(), Subscription{URL: panel.URL, ForceHWID: true}, "Happ", nil, false)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("загрузка через VPN: err=%v nodes=%d", err, len(nodes))
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
