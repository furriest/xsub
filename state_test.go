package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Битый файл состояния не должен лишать xsub запуска: readStateFile подхватывает
// .bak-копию, а loadConfig с повреждённым settings.json продолжает с config.json.
func TestStateFileBackupRecovery(t *testing.T) {
	dir := t.TempDir()
	c := defaultConfig()
	c.dir = dir

	good := []byte(`[{"name":"Основная","url":"https://example.com/sub"}]`)
	if err := os.WriteFile(filepath.Join(dir, subsFile+".bak"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, subsFile), []byte("{не json"), 0o600); err != nil {
		t.Fatal(err)
	}
	subs, err := loadSubs(c)
	if err != nil || len(subs) != 1 || subs[0].Name != "Основная" {
		t.Fatalf("ожидалась .bak-копия: %v %+v", err, subs)
	}

	// Оба битых — ошибка, но newApp не падает, а продолжает без подписок.
	if err := os.WriteFile(filepath.Join(dir, subsFile+".bak"), []byte("тоже бито"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSubs(c); err == nil {
		t.Fatal("два битых файла должны давать ошибку")
	}
	c.Password = "pw"
	c.Xray.Bin = filepath.Join(dir, "xray")
	a, err := newApp(c)
	if err != nil || a == nil {
		t.Fatalf("newApp при битых подписках: %v", err)
	}
	if len(a.subs) != 0 {
		t.Fatalf("подписок быть не должно: %+v", a.subs)
	}
}

func TestWriteStateFileKeepsBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, groupsFile)
	if err := writeStateFile(p, []byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p + ".bak")
	if err != nil || string(b) != "[]" {
		t.Fatalf(".bak-копия не создана: %v %q", err, b)
	}
	// Повреждаем основной файл — loadGroups обязан поднять копию.
	if err := os.WriteFile(p, []byte("бито"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := defaultConfig()
	c.dir = dir
	gs, err := loadGroups(c)
	if err != nil || gs == nil {
		t.Fatalf("loadGroups из .bak: %v %+v", err, gs)
	}
}

func TestLoadConfigToleratesBrokenSettings(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte(`{"password":"pw"}`), 0o600)
	os.WriteFile(filepath.Join(dir, settingsFile), []byte("{бито"), 0o600)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatalf("битый settings.json не должен мешать запуску: %v", err)
	}
	if c.Password != "pw" {
		t.Fatalf("config.json не прочитался: %+v", c)
	}
	// Чиним .bak — подхватываем его.
	os.WriteFile(filepath.Join(dir, settingsFile+".bak"), []byte(`{"max_nodes":25}`), 0o600)
	c, err = loadConfig(p)
	if err != nil || c.MaxNodes != 25 {
		t.Fatalf(".bak settings.json: %v max_nodes=%d", err, c.MaxNodes)
	}
}
