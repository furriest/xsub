package main

import (
	"context"
	"os"
	"testing"
)

// Сохранение без применения: файлы записаны, флаг pending_apply поднят,
// конфиг не тронут; applySaved применяет и флаг снимает.
func TestSaveWithoutApply(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	c.Xray.Bin = fakeXray(t)
	c.Xray.RestartCmd = "true"
	a, err := newApp(c)
	if err != nil {
		t.Fatal(err)
	}

	if err := a.saveList(context.Background(), "vpn", "one.example\n", false); err != nil {
		t.Fatal(err)
	}
	if !a.pendingApply.Load() {
		t.Fatal("после сохранения без применения pending_apply должен быть поднят")
	}
	if b, _ := os.ReadFile(c.path("vpn.txt")); string(b) != "one.example\n" {
		t.Fatalf("файл не записан: %q", b)
	}

	// Повторное сохранение с применением снимает флаг.
	if err := a.saveList(context.Background(), "vpn", "one.example\ntwo.example\n", true); err != nil {
		t.Fatal(err)
	}
	if a.pendingApply.Load() {
		t.Fatal("после применения pending_apply должен быть снят")
	}

	// Сохранение групп без применения тоже поднимает флаг; applySaved снимает.
	if err := a.saveGroups([]Group{{ID: "g1", Name: "G", Filter: "x"}}, map[string]string{"g1": "g.example\n"}, false); err != nil {
		t.Fatal(err)
	}
	if !a.pendingApply.Load() {
		t.Fatal("saveGroups без применения должен поднимать pending_apply")
	}
	if err := a.applySaved(); err != nil {
		t.Fatal(err)
	}
	if a.pendingApply.Load() {
		t.Fatal("applySaved должен снимать pending_apply")
	}
	if b, _ := os.ReadFile(c.path("group-g1.txt")); string(b) != "g.example\n" {
		t.Fatalf("список группы не записан: %q", b)
	}
}
