package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// repoRe — «владелец/репозиторий» на GitHub. Значение из config.json попадает и в
// ссылку, и в строку, которую выполняет /bin/sh, поэтому проверяется до использования.
var repoRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)

func validRepo(s string) bool { return repoRe.MatchString(s) }

// newerVersion: true, если b новее a (сравнение x.y.z).
func newerVersion(a, b string) bool {
	pa, pb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return y > x
		}
	}
	return false
}

// checkUpdate узнаёт последнюю версию на GitHub (раз в сутки).
func (a *App) checkUpdate(ctx context.Context) {
	if !validRepo(a.c.UpdateRepo) {
		return
	}
	b, _, err := fetchURL(ctx, a.c, "https://api.github.com/repos/"+a.c.UpdateRepo+"/releases/latest", "xsub/"+version, 1<<20)
	if err != nil {
		return
	}
	var r struct {
		Tag string `json:"tag_name"`
	}
	if json.Unmarshal(b, &r) != nil || r.Tag == "" {
		return
	}
	latest := strings.TrimPrefix(r.Tag, "v")
	a.mu.Lock()
	a.latest = latest
	a.mu.Unlock()
	if newerVersion(version, latest) && a.c.Telegram.OnUpdate {
		a.n.send("update"+latest, fmt.Sprintf("вышла новая версия xsub %s (сейчас %s) — обновить можно на странице xsub", latest, version), 365*24*time.Hour)
	}
}

const updateLog = "/tmp/xsub-update.log"

func ipkArch() string { return ipkArchOf(runtime.GOARCH) }

// ipkArchOf — как архитектура Go называется в именах пакетов релиза (см. scripts/build.sh).
// Пустая строка — для этой архитектуры пакетов не собирают.
func ipkArchOf(goarch string) string {
	switch goarch {
	case "arm64":
		return "aarch64"
	case "mipsle":
		return "mipsel"
	case "mips":
		return "mips"
	case "arm":
		return "armv7"
	}
	return ""
}

// upLog дописывает строку в журнал обновления — его показывает страница.
func upLog(format string, v ...any) {
	f, err := os.OpenFile(updateLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, v...))
	f.Close()
}

// sumFor — контрольная сумма файла из SHA256SUMS.
func sumFor(sums, name string) string {
	for _, l := range strings.Split(sums, "\n") {
		if f := strings.Fields(l); len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// startUpgrade скачивает пакет и запускает установку. Качает именно xsub, а не opkg:
// fetchURL умеет ходить через VPN, когда GitHub недоступен напрямую. Раньше обновление
// начиналось с «opkg update», который про VPN не знает, — на заблокированном канале он
// молча висел, держа opkg.lock, и обновление не двигалось вообще.
func (a *App) startUpgrade() error {
	if !validRepo(a.c.UpdateRepo) {
		return fmt.Errorf("update_repo в config.json должен быть вида владелец/репозиторий")
	}
	if _, err := exec.LookPath("opkg"); err != nil {
		return fmt.Errorf("не найден opkg")
	}
	arch := ipkArch()
	if arch == "" {
		return fmt.Errorf("для архитектуры %s пакета нет — обновите вручную", runtime.GOARCH)
	}
	if !a.upgrading.CompareAndSwap(false, true) {
		return fmt.Errorf("обновление уже идёт — смотрите журнал обновления")
	}
	_ = os.WriteFile(updateLog, nil, 0o600)
	upLog("обновление xsub %s → %s", version, a.latestVersion())
	goSafe("обновлении xsub", func() {
		if err := a.upgrade(arch); err != nil {
			upLog("не вышло: %v", err)
			a.upgrading.Store(false)
		}
	})
	lg.Printf("запущено обновление xsub (журнал: %s)", updateLog)
	return nil
}

func (a *App) latestVersion() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.latest
}

// upgrade качает пакет, сверяет контрольную сумму и отдаёт его opkg.
func (a *App) upgrade(arch string) error {
	base := "https://github.com/" + a.c.UpdateRepo + "/releases/latest/download"
	name := "xsub_" + arch + ".ipk"

	upLog("скачиваю SHA256SUMS")
	sums, _, err := fetchURL(context.Background(), a.c, base+"/SHA256SUMS", "xsub/"+version, 1<<20)
	if err != nil {
		return fmt.Errorf("SHA256SUMS: %v", err)
	}
	want := sumFor(string(sums), name)
	if want == "" {
		return fmt.Errorf("в SHA256SUMS нет %s", name)
	}

	upLog("скачиваю %s", name)
	pkg, _, err := fetchURL(context.Background(), a.c, base+"/"+name, "xsub/"+version, 64<<20)
	if err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(pkg)); got != want {
		return fmt.Errorf("контрольная сумма пакета не совпала — обновление отменено")
	}

	path := filepath.Join("/tmp", name)
	if err := os.WriteFile(path, pkg, 0o600); err != nil {
		return err
	}
	upLog("скачано %d КБ, ставлю пакет", len(pkg)>>10)
	return a.installPackage(path)
}

// installPackage ставит пакет отдельным процессом: opkg остановит и снова запустит
// xsub, поэтому ждать окончания сам xsub не может.
func (a *App) installPackage(path string) error {
	script := "sleep 1\nopkg install '" + path + "' 2>&1\n" +
		`echo "$(date '+%F %T') готово, код $?"` + "\nrm -f '" + path + "'"
	f, err := os.OpenFile(updateLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.Env = append(os.Environ(), "PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Если установка не удалась и xsub остался жив, кнопку надо вернуть в рабочее состояние.
	goSafe("установке пакета", func() {
		_ = cmd.Wait()
		a.upgrading.Store(false)
	})
	return nil
}
