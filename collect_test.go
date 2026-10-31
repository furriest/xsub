package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fakeXray — «ядро», которое принимает любой конфиг: подставляет вместо
// настоящего xray там, где тесту нужен проходной xray -test.
func fakeXray(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("тест рассчитан на unix")
	}
	p := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// Ускоренное ожидание загрузки ядра: тестовый «xray» никогда не бывает
// запущен как процесс, и afterRestart отсчитывал бы полные 20 секунд.
func fastConfig(t *testing.T) *Config {
	t.Helper()
	old := xrayBootPolls
	xrayBootPolls = 1
	t.Cleanup(func() { xrayBootPolls = old })
	c := defaultConfig()
	c.Watch.RestartDelaySec = 1
	return c
}

// Регрессия: обновление подписки не должно терять узлы. Ловит теневое
// переобъявление nodes/warns в collect: загрузка и парсинг проходили успешно,
// а в apply() уходил nil — на роутере это выглядело как «после обновления все
// узлы пропали, остался только резерв».
func TestRefreshSubsKeepsNodes(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(
		"vless://2d32250e-fb36-4495-bf21-07fa0b2e7f9d@nl.example.com:443?encryption=none&security=reality&sni=a.example&pbk=4oPjFhCGYBbtVD2aCoA4x3EULVckDGWQYjvci2tp6Jo#NL\n" +
			"vless://2d32250e-fb36-4495-bf21-07fa0b2e7f9d@de.example.com:443?encryption=none&security=reality&sni=a.example&pbk=4oPjFhCGYBbtVD2aCoA4x3EULVckDGWQYjvci2tp6Jo#DE\n"))
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer panel.Close()

	c := fastConfig(t)
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	c.Xray.Bin = fakeXray(t)
	c.Xray.RestartCmd = "true"
	a, err := newApp(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.saveSubs([]Subscription{{Name: "основная", URL: panel.URL}}); err != nil {
		t.Fatal(err)
	}
	if failed := a.refreshSubs(context.Background()); failed {
		t.Fatal("обновление подписки не должно считаться неудачным")
	}
	a.mu.Lock()
	st := a.states[panel.URL]
	a.mu.Unlock()
	if st.Err != "" || st.Nodes != 2 {
		t.Fatalf("подписка: err=%q nodes=%d", st.Err, st.Nodes)
	}
	a.w.mu.Lock()
	defer a.w.mu.Unlock()
	if len(a.w.nodes) != 2 {
		t.Fatalf("сторож получил %d узлов, ожидалось 2", len(a.w.nodes))
	}
}

// Панель с лимитом устройств: без HWID отдаёт заглушки, с HWID — узлы.
// HWID отправляется только в повторном запросе и сохраняется в файле hwid.
func TestRefreshSubsHWIDPanel(t *testing.T) {
	full := `[{"remarks":"NL","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"2d32250e-fb36-4495-bf21-07fa0b2e7f9d","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}]}]`
	stub := "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp#Включите отправку HWID"
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hwid") == "" {
			w.Write([]byte(stub))
			return
		}
		w.Write([]byte(full))
	}))
	defer panel.Close()

	c := fastConfig(t)
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	c.Xray.Bin = fakeXray(t)
	c.Xray.RestartCmd = "true"
	a, err := newApp(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.saveSubs([]Subscription{{Name: "rw", URL: panel.URL}}); err != nil {
		t.Fatal(err)
	}
	if failed := a.refreshSubs(context.Background()); failed {
		t.Fatal("обновление не должно считаться неудачным")
	}
	a.mu.Lock()
	st := a.states[panel.URL]
	a.mu.Unlock()
	if st.Err != "" || st.Nodes != 1 {
		t.Fatalf("подписка с HWID: err=%q nodes=%d", st.Err, st.Nodes)
	}
	if _, err := os.Stat(c.path("hwid")); err != nil {
		t.Fatal("файл hwid должен быть создан после обновления с HWID")
	}
}
