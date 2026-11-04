package main

import (
	"os"
	"testing"
)

func checkTestApp(t *testing.T, files map[string]string) *App {
	t.Helper()
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Watch.StatsFile = ""
	for name, body := range files {
		if err := os.WriteFile(c.path(name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &App{c: c, w: newWatcher(c)}
}

// Группа ловит домен раньше общего списка «Через VPN» — и проверка это видит.
func TestCheckTargetGroupPlain(t *testing.T) {
	a := checkTestApp(t, map[string]string{
		"vpn.txt":      "anthropic.com\n",
		"groups.json":  `[{"id":"g1","name":"anthropic","filter":"(?i)us"}]`,
		"group-g1.txt": "claude.anthropic.com\nanthropic.com\n",
	})
	res := a.checkTarget("claude.anthropic.com")
	if res.Route != "group" || res.Target != "anthropic" {
		t.Fatalf("route=%q target=%q list=%q", res.Route, res.Target, res.List)
	}
	res = a.checkTarget("anthropic.com")
	if res.Route != "group" {
		t.Fatalf("домен из обоих списков должен идти в группу: route=%q", res.Route)
	}
}

// Регрессия из поля: в списке группы — внешний список в классическом формате.
// Проверка сайта обязана разбирать его так же полно, как маршрутизация.
func TestCheckTargetGroupRemote(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Watch.StatsFile = ""
	aiURL := "https://example.com/ai.list"
	classic := "DOMAIN-SUFFIX,anthropic.com\nDOMAIN,claude.anthropic.com\n"
	os.MkdirAll(c.path("remote"), 0o700)
	if err := os.WriteFile(remotePath(c, aiURL), []byte(classic), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"vpn.txt":      "anthropic.com\n",
		"groups.json":  `[{"id":"g1","name":"anthropic","filter":"(?i)us"}]`,
		"group-g1.txt": aiURL + "\n",
	} {
		if err := os.WriteFile(c.path(name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := &App{c: c, w: newWatcher(c)}
	res := a.checkTarget("claude.anthropic.com")
	if res.Route != "group" {
		t.Fatalf("route=%q target=%q list=%q rule=%q notes=%v", res.Route, res.Target, res.List, res.Rule, res.Notes)
	}
	if res.Rule == "" {
		t.Fatal("правило должно показывать строку внешнего списка")
	}
}
