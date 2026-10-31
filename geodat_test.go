package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Сборка маленького geosite.dat, чтобы разбор проверялся без настоящих файлов Xray.

func pbLen(field int, b []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(field)<<3|2)
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}

func pbVar(field int, v uint64) []byte {
	out := binary.AppendUvarint(nil, uint64(field)<<3)
	return binary.AppendUvarint(out, v)
}

type geoCat struct {
	code    string
	domains []string
}

// buildGeoSite складывает файл формата v2fly: поток записей «категория + домены».
func buildGeoSite(cats []geoCat) []byte {
	var out []byte
	for _, c := range cats {
		body := pbLen(1, []byte(c.code))
		for _, d := range c.domains {
			dom := append(pbVar(1, 2), pbLen(2, []byte(d))...) // тип 2 — домен с поддоменами
			body = append(body, pbLen(2, dom)...)
		}
		out = append(out, pbLen(1, body)...)
	}
	return out
}

func writeDat(t *testing.T, b []byte) *Config {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.dat"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	c := defaultConfig()
	c.Xray.AssetDir = dir
	geoCache.reset()
	t.Cleanup(geoCache.reset)
	return c
}

func TestGeoSiteSynthetic(t *testing.T) {
	// Вторая категория заведомо больше буфера bufio: пропуская её, разбор обязан
	// дочитать запись до конца, иначе следующая прочитается как мусор.
	big := make([]string, 3000)
	for i := range big {
		big[i] = fmt.Sprintf("host%04d.example", i)
	}
	c := writeDat(t, buildGeoSite([]geoCat{
		{"FIRST", []string{"a.example"}},
		{"BIG", big},
		{"TELEGRAM", []string{"t.me", "telegram.org"}},
	}))

	d, err := geoSite(c, "test.dat", "telegram") // регистр категории не важен
	if err != nil {
		t.Fatalf("категория после большой пропущенной не прочиталась: %v", err)
	}
	if len(d) != 2 || d[0].value != "t.me" || d[1].value != "telegram.org" {
		t.Fatalf("%+v", d)
	}
	if d[0].typ != 2 {
		t.Errorf("тип домена %d", d[0].typ)
	}
	if first, err := geoSite(c, "test.dat", "FIRST"); err != nil || len(first) != 1 {
		t.Errorf("первая категория: %v %d", err, len(first))
	}
	if _, err := geoSite(c, "test.dat", "нет-такой"); err == nil {
		t.Error("несуществующая категория должна давать ошибку")
	}
	// Повторный вызов идёт из кэша.
	if d2, err := geoSite(c, "test.dat", "telegram"); err != nil || len(d2) != 2 {
		t.Errorf("из кэша: %v", err)
	}
}

func TestGeoCacheEvictsByBudget(t *testing.T) {
	geoCache.reset()
	defer geoCache.reset()
	mk := func(n int) []geoDomain {
		d := make([]geoDomain, n)
		for i := range d {
			d[i] = geoDomain{typ: 2, value: "h.example"}
		}
		return d
	}
	geoCache.mu.Lock()
	geoCache.putSite("big", mk(maxGeoSiteEntries))
	geoCache.putSite("small", mk(10))
	_, bigOK := geoCache.site["big"]
	_, smallOK := geoCache.site["small"]
	siteN := geoCache.siteN
	geoCache.mu.Unlock()
	if !smallOK || bigOK {
		t.Fatalf("старейшая категория должна вытесняться ради бюджета: big=%v small=%v", bigOK, smallOK)
	}
	if siteN != 10 {
		t.Fatalf("счётчик записей: %d", siteN)
	}

	// Категория больше бюджета в одиночку остаётся — иначе кэш не работал бы вообще.
	geoCache.reset()
	geoCache.mu.Lock()
	geoCache.putSite("huge", mk(maxGeoSiteEntries+1000))
	_, hugeOK := geoCache.site["huge"]
	geoCache.mu.Unlock()
	if !hugeOK {
		t.Fatal("одиночная категория больше бюджета должна остаться в кэше")
	}
}

func TestGeoSiteCorrupt(t *testing.T) {
	// Запись, объявившая длину в терабайт: раньше это был make([]byte, l) и паника.
	huge := binary.AppendUvarint([]byte{byte(1<<3 | 2)}, 1<<42)
	c := writeDat(t, huge)
	if _, err := geoSite(c, "test.dat", "любая"); err == nil {
		t.Error("битая длина записи должна давать ошибку")
	}

	// Та же история с кодом категории внутри записи.
	inner := binary.AppendUvarint([]byte{byte(1<<3 | 2)}, 1<<42)
	c = writeDat(t, pbLen(1, inner))
	if _, err := geoSite(c, "test.dat", "любая"); err == nil {
		t.Error("битая длина кода категории должна давать ошибку")
	}
}
