package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Дефолты живут в двух местах: шаблоне для «xsub -init» (main.go) и defaultConfig()
// (config.go). Расхождение — баг: новая установка получит настройки, отличные
// от тех, с которыми стартуют без конфига. Пароль в шаблоне подставляется
// форматированием — подставляем тестовый.
func TestDefaultConfigMatchesInitTemplate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(fmt.Sprintf(defaultConfigJSON, "test-password-1")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(p)
	if err != nil {
		t.Fatalf("шаблон из main.go не читается loadConfig: %v", err)
	}
	got.dir = ""      // loadConfig проставляет путь к конфигу — на сравнение не влияет
	got.Password = "" // в шаблон подставляется случайный пароль — не часть дефолтов
	if want := defaultConfig(); !reflect.DeepEqual(got, want) {
		t.Errorf("defaultConfigJSON (main.go) и defaultConfig() (config.go) разошлись:\n got: %+v\nwant: %+v", got, want)
	}
}

// Серверный режим (Docker): роутерные дефолты заменяются серверными, явные
// значения админа в config.json побеждают, stats_file получает путь в папке
// конфига, чтобы история проверок переживала пересоздание контейнера.
func TestServerModeDefaults(t *testing.T) {
	old := serverMode
	serverMode = true
	defer func() { serverMode = old }()

	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"password":"test-password-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Xray.Bin != "/usr/local/bin/xray" {
		t.Errorf("xray.bin: %q", c.Xray.Bin)
	}
	if c.Xray.ConfDir != "/data/xray" || c.Xray.AssetDir != "/data/xray" {
		t.Errorf("confdir/assetdir: %q / %q", c.Xray.ConfDir, c.Xray.AssetDir)
	}
	if c.Xray.RestartCmd != "/usr/local/bin/xsub-xray-restart" {
		t.Errorf("restart_cmd: %q", c.Xray.RestartCmd)
	}
	if len(c.Xray.ForceProxyInbounds) != 1 || c.Xray.ForceProxyInbounds[0] != "in-socks" {
		t.Errorf("force_proxy_inbounds: %v", c.Xray.ForceProxyInbounds)
	}
	if c.LogFile != "" {
		t.Errorf("log_file: %q — в контейнере журнал должен идти в stdout", c.LogFile)
	}
	if want := filepath.Join(dir, "xsub-stats.json"); c.Watch.StatsFile != want {
		t.Errorf("stats_file: %q, want %q", c.Watch.StatsFile, want)
	}

	// Явно заданные админом значения не затираются подстройкой.
	custom := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(custom, []byte(`{
		"password": "test-password-1",
		"xray": {"restart_cmd": "/bin/my-restart", "force_proxy_inbounds": []}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := loadConfig(custom)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Xray.RestartCmd != "/bin/my-restart" {
		t.Errorf("явный restart_cmd затирается: %q", c2.Xray.RestartCmd)
	}
	if len(c2.Xray.ForceProxyInbounds) != 0 {
		t.Errorf("явный пустой force_proxy_inbounds затирается: %v", c2.Xray.ForceProxyInbounds)
	}

	// Серверный шаблон для «xsub -init» должен читаться без ошибок.
	tmpl := filepath.Join(dir, "init.json")
	if err := os.WriteFile(tmpl, []byte(fmt.Sprintf(defaultConfigJSONServer, "test-password-1")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(tmpl); err != nil {
		t.Errorf("defaultConfigJSONServer не читается loadConfig: %v", err)
	}
}
