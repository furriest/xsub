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
