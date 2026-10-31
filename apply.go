package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// opMu — одна «тяжёлая» операция за раз: применение конфига, обновление geo, выбор узла.
var opMu sync.Mutex

func xrayEnv(c *Config) []string {
	return append(os.Environ(), "XRAY_LOCATION_ASSET="+c.Xray.AssetDir)
}

func runCmd(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = env
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// xrayTest проверяет конфиг из папки dir. Возвращает хвост вывода при ошибке.
func xrayTest(c *Config, dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := runCmd(ctx, xrayEnv(c), c.Xray.Bin, "run", "-test", "-confdir", dir)
	if err != nil {
		return fmt.Errorf("xray -test: %v\n%s", err, tail(out, 6))
	}
	return nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func restartXray(c *Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := runCmd(ctx, nil, "/bin/sh", "-c", c.Xray.RestartCmd)
	if err != nil {
		return fmt.Errorf("%s: %v\n%s", c.Xray.RestartCmd, err, tail(out, 6))
	}
	return nil
}

func originalDir(c *Config) string { return c.path(filepath.Join("backup", "original")) }

// managed — xsub уже хотя бы раз записал конфиг Xray (сохранены исходные файлы).
func managed(c *Config) bool {
	_, err := os.Stat(filepath.Join(originalDir(c), ".saved"))
	return err == nil
}

// saveOriginals один раз сохраняет исходные 05_routing.json/07_xsub.json — для -restore и удаления пакета.
func saveOriginals(c *Config) error {
	if managed(c) {
		return nil
	}
	dir := originalDir(c)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range []string{routingFile, xsubFile} {
		b, err := os.ReadFile(filepath.Join(c.Xray.ConfDir, f))
		if err == nil {
			if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
				return err
			}
		}
	}
	return os.WriteFile(filepath.Join(dir, ".saved"), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600)
}

// restoreOriginals возвращает конфиги Xray к состоянию до xsub и перезапускает Xray.
func restoreOriginals(c *Config) error {
	if !managed(c) {
		return fmt.Errorf("xsub ещё не менял конфиги Xray — восстанавливать нечего")
	}
	dir := originalDir(c)
	for _, f := range []string{routingFile, xsubFile} {
		dst := filepath.Join(c.Xray.ConfDir, f)
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err == nil {
			if err := writeAtomic(dst, b); err != nil {
				return err
			}
		} else {
			_ = os.Remove(dst)
		}
	}
	_ = os.Remove(filepath.Join(dir, ".saved"))
	return restartXray(c)
}

// applyConfig генерирует конфиг, проверяет его копию через xray -test и только потом
// подменяет файлы и перезапускает Xray. Возвращает changed=false, если менять нечего.
// Вызывать под opMu; env (окружение конфигов Xray) передаётся из apply — не перечитывать.
func applyConfig(c *Config, env Env, nodes, fbs []Node, reason string) (changed bool, err error) {
	rs, lerrs, err := readRouting(c)
	if err != nil {
		return false, err
	}
	if len(lerrs) > 0 {
		return false, fmt.Errorf("ошибки в списках:\n%s", strings.Join(lerrs, "\n"))
	}
	routing, xsub, err := generate(c, env, nodes, fbs, rs)
	if err != nil {
		return false, err
	}
	rPath := filepath.Join(c.Xray.ConfDir, routingFile)
	xPath := filepath.Join(c.Xray.ConfDir, xsubFile)
	oldR, _ := os.ReadFile(rPath)
	oldX, _ := os.ReadFile(xPath)
	if bytes.Equal(oldR, routing) && bytes.Equal(oldX, xsub) {
		return false, nil
	}

	// Проверка во временной копии папки конфигов.
	tmp, err := os.MkdirTemp("", "xsub-test-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	files, _ := filepath.Glob(filepath.Join(c.Xray.ConfDir, "*.json"))
	for _, f := range files {
		base := filepath.Base(f)
		if base == routingFile || base == xsubFile {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return false, err
		}
		if err := os.WriteFile(filepath.Join(tmp, base), b, 0o600); err != nil {
			return false, err
		}
	}
	_ = os.WriteFile(filepath.Join(tmp, routingFile), routing, 0o600)
	_ = os.WriteFile(filepath.Join(tmp, xsubFile), xsub, 0o600)
	if err := xrayTest(c, tmp); err != nil {
		return false, err
	}

	if err := saveOriginals(c); err != nil {
		return false, fmt.Errorf("не удалось сохранить исходные конфиги: %v", err)
	}
	bdir := c.path("backup")
	if len(oldR) > 0 {
		_ = os.WriteFile(filepath.Join(bdir, routingFile), oldR, 0o600)
	}
	if len(oldX) > 0 {
		_ = os.WriteFile(filepath.Join(bdir, xsubFile), oldX, 0o600)
	}
	if err := writeAtomic(xPath, xsub); err != nil {
		return false, err
	}
	if err := writeAtomic(rPath, routing); err != nil {
		return false, err
	}
	lg.Printf("конфиг Xray обновлён (%s), узлов: %d, резервов: %d — перезапускаю Xray", reason, len(nodes), len(fbs))
	if err := restartXray(c); err != nil {
		lg.Printf("ошибка перезапуска: %v — возвращаю прежний конфиг", err)
		restoreFiles(c, oldR, oldX)
		_ = restartXray(c)
		return false, err
	}
	return true, nil
}

func restoreFiles(c *Config, oldR, oldX []byte) {
	rPath := filepath.Join(c.Xray.ConfDir, routingFile)
	xPath := filepath.Join(c.Xray.ConfDir, xsubFile)
	if len(oldR) > 0 {
		_ = writeAtomic(rPath, oldR)
	}
	if len(oldX) > 0 {
		_ = writeAtomic(xPath, oldX)
	} else {
		_ = os.Remove(xPath)
	}
}

func writeAtomic(path string, b []byte) error { return writeAtomicMode(path, b, 0o644) }

// writeAtomicMode пишет во временный файл рядом и переименовывает. Данные сбрасываются
// на носитель до переименования, а каталог — после: роутер выключают из розетки, и без
// этого после перезагрузки на месте конфига мог оказаться файл нулевой длины.
// Имя временного файла уникально — иначе два писателя в один путь затрут друг друга.
func writeAtomicMode(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".xsub-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		f.Close()
		os.Remove(tmp) // после удачного Rename файла уже нет, ошибка не важна
	}()
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir закрепляет само переименование. На части файловых систем роутеров
// каталог открыть на чтение нельзя — тогда просто пропускаем.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// testOutbounds проверяет через xray -test только набор outbound'ов узлов.
func testOutbounds(c *Config, nodes []Node) error {
	tmp, err := os.MkdirTemp("", "xsub-nodes-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	var obs []any
	for _, n := range nodes {
		obs = append(obs, n.Outbound)
	}
	b, err := marshal(map[string]any{"outbounds": obs})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, "nodes.json"), b, 0o600); err != nil {
		return err
	}
	return xrayTest(c, tmp)
}

// validateNodes отсеивает узлы, которые не принимает установленный Xray
// (например, новый транспорт на старом ядре), чтобы один узел не ломал весь конфиг.
// Плохие узлы ищутся делением пополам: каждая проверка — это запуск xray -test
// отдельным процессом, а на mipsel он занимает секунды. Набор, прошедший целиком,
// принимается одним запуском, поэтому при одном плохом узле из шестидесяти выходит
// около десятка запусков вместо шестидесяти.
func validateNodes(c *Config, nodes []Node) (good []Node, bad []string) {
	return bisectNodes(nodes, func(ns []Node) error { return testOutbounds(c, ns) })
}

// bisectNodes делит набор пополам, пока не найдёт каждый непринимаемый узел.
// test — проверка набора целиком; вынесена параметром, чтобы обходиться без Xray в тестах.
func bisectNodes(nodes []Node, test func([]Node) error) (good []Node, bad []string) {
	var walk func(ns []Node)
	walk = func(ns []Node) {
		if len(ns) == 0 {
			return
		}
		err := test(ns)
		if err == nil {
			good = append(good, ns...)
			return
		}
		if len(ns) > 1 {
			mid := len(ns) / 2 // порядок узлов сохраняется: сначала левая половина
			walk(ns[:mid])
			walk(ns[mid:])
			return
		}
		n := ns[0]
		// Для более старых версий Xray пробуем упрощённый вариант узла.
		if alt, note, ok := legacyVariant(n); ok && test([]Node{alt}) == nil {
			lg.Printf("%s: %s", n.Name, note)
			good = append(good, alt)
			return
		}
		bad = append(bad, fmt.Sprintf("%s: Xray не принял узел (%s)", n.Name, xrayReason(err)))
	}
	walk(nodes)
	return good, bad
}

// xrayReason вытаскивает из вывода xray -test последнюю, самую внятную часть.
func xrayReason(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, " > "); i >= 0 {
		msg = msg[i+3:]
	}
	return strings.TrimSpace(strings.SplitN(msg, "\n", 2)[0])
}

// legacyVariant переписывает узел под Xray до 26.10: без перебора портов (udphop)
// и с прежними названиями масок mKCP (mkcp-original / mkcp-aes128gcm / header-*).
func legacyVariant(n Node) (Node, string, bool) {
	b, err := json.Marshal(n.Outbound)
	if err != nil {
		return n, "", false
	}
	var ob map[string]any
	if json.Unmarshal(b, &ob) != nil {
		return n, "", false
	}
	ss, _ := ob["streamSettings"].(map[string]any)
	fm, _ := ss["finalmask"].(map[string]any)
	udp, _ := fm["udp"].([]any)
	if len(udp) == 0 {
		return n, "", false
	}
	var out []any
	var notes []string
	changed := false
	for _, m := range udp {
		mm, _ := m.(map[string]any)
		st, _ := mm["settings"].(map[string]any)
		switch mm["type"] {
		case "udphop":
			changed = true
			notes = append(notes, "эта версия Xray не умеет перебор портов — используется основной порт")
		case "mkcp-legacy":
			changed = true
			switch {
			case anyStr(st["header"]) != "":
				out = append(out, map[string]any{"type": "header-" + anyStr(st["header"])})
			case anyStr(st["value"]) != "":
				out = append(out, map[string]any{"type": "mkcp-aes128gcm", "settings": map[string]any{"password": anyStr(st["value"])}})
			default:
				out = append(out, map[string]any{"type": "mkcp-original"})
			}
			notes = append(notes, "mKCP настроен в формате Xray до 26.10")
		default:
			out = append(out, m)
		}
	}
	if !changed {
		return n, "", false
	}
	if len(out) > 0 {
		fm["udp"] = out
	} else {
		delete(ss, "finalmask")
	}
	n.Outbound = ob
	n.Warn = strings.Join(notes, "; ")
	return n, n.Warn, true
}
