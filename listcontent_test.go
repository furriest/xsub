package main

import (
	"os"
	"testing"
)

// Экран «состав списка»: локальный файл и внешние списки разбираются
// теми же парсерами, что и при применении, и раскладываются по типам.
func TestListContent(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	aiURL := "https://example.com/ai.list"
	classic := "DOMAIN-SUFFIX,anthropic.com\nDOMAIN,claude.anthropic.com\nIP-CIDR,203.0.113.0/24\nPROCESS-NAME,chrome\n"
	if err := os.MkdirAll(c.path("remote"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(remotePath(c, aiURL), []byte(classic), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "example.com\n=exact.example.com\n1.2.3.0/24\nплохо но!!\n" + aiURL + "\nhttps://example.com/missing.list\n"
	if err := os.WriteFile(c.path("vpn.txt"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	lc := listContent(c, "vpn.txt")
	if lc.File != "vpn.txt" || lc.Local == nil {
		t.Fatalf("file/local: %+v", lc)
	}
	loc := lc.Local
	if loc.Counts["domain"] != 1 || loc.Counts["full"] != 1 || loc.Counts["ip"] != 1 {
		t.Fatalf("local counts: %v", loc.Counts)
	}
	if len(loc.Errors) != 1 {
		t.Fatalf("local errors: %v", loc.Errors)
	}
	if len(lc.Remotes) != 2 {
		t.Fatalf("remotes: %d", len(lc.Remotes))
	}
	ok, missing := lc.Remotes[0], lc.Remotes[1]
	if !ok.Cached || ok.Counts["domain"] != 1 || ok.Counts["full"] != 1 || ok.Counts["ip"] != 1 || ok.Skipped != 1 {
		t.Fatalf("remote cached: %+v", ok)
	}
	if missing.Cached || missing.Counts != nil {
		t.Fatalf("remote missing: %+v", missing)
	}
	// Итог: сумма локального и скачанных внешних списков.
	if lc.Total.Counts["domain"] != 2 || lc.Total.Counts["full"] != 2 || lc.Total.Counts["ip"] != 2 || lc.Total.Skipped != 1 {
		t.Fatalf("total: %+v", lc.Total)
	}
	if len(lc.Total.Entries["domain"]) != 2 || len(lc.Total.Entries["full"]) != 2 {
		t.Fatalf("total entries: %v", lc.Total.Entries)
	}
}
