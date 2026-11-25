package main

import (
	"context"
	"strings"
	"testing"
)

const tLinks = "socks5://user:pass@203.0.113.5:1080#SOCKS\n" +
	"vless://" + tUUID + "@nl.example.com:443?encryption=none&security=reality&sni=a.example&pbk=4oPjFhCGYBbtVD2aCoA4x3EULVckDGWQYjvci2tp6Jo#NL\n"

func TestValidateSubsManualLinks(t *testing.T) {
	ok := []Subscription{
		{Name: "свои", Links: tLinks},
		{Name: "панель", URL: "https://panel.example/sub"},
	}
	if err := validateSubs(ok); err != nil {
		t.Fatalf("подписка ссылками должна приниматься: %v", err)
	}
	for name, subs := range map[string][]Subscription{
		"и адрес, и ссылки": {{Name: "x", URL: "https://p.example/s", Links: tLinks}},
		"ни одного узла":    {{Name: "x", Links: "просто текст\n"}},
		"повтор ссылок":     {{Name: "a", Links: tLinks}, {Name: "b", Links: tLinks}},
		"пусто":             {{Name: "x"}},
	} {
		if err := validateSubs(subs); err == nil {
			t.Errorf("%s: должна быть ошибка", name)
		}
	}
}

// Узлы, вставленные ссылками, собираются без сети и попадают к сторожу,
// как узлы подписки; состояние подписки — по ключу ссылок.
func TestCollectManualLinks(t *testing.T) {
	c := fastConfig(t)
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	c.Xray.Bin = fakeXray(t)
	c.Xray.RestartCmd = "true"
	a, err := newApp(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.waitSettle)
	s := Subscription{Name: "свои", Links: tLinks}
	a.mu.Lock()
	a.subs = []Subscription{s}
	a.mu.Unlock()
	nodes := a.collect(context.Background(), true)
	if len(nodes) != 2 {
		t.Fatalf("узлов %d, ожидалось 2", len(nodes))
	}
	var socks bool
	for _, n := range nodes {
		if strings.Contains(string(mustMarshal(n.Outbound)), `"socks"`) {
			socks = true
		}
	}
	if !socks {
		t.Fatal("socks5-ссылка не превратилась в outbound socks")
	}
	a.mu.Lock()
	st := a.states[s.key()]
	a.mu.Unlock()
	if st == nil || !st.Manual || st.Nodes != 2 || st.Err != "" {
		t.Fatalf("состояние подписки ссылками: %+v", st)
	}
}
