package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// UISettings — то, что можно поменять на веб-странице. Хранится в settings.json поверх config.json.
type UISettings struct {
	Password         string `json:"password,omitempty"`
	SubIntervalHours int    `json:"sub_interval_hours"`
	UserAgent        string `json:"user_agent"`
	MaxNodes         int    `json:"max_nodes"`
	LogFile          string `json:"log_file"`
	UIAllowWAN       bool   `json:"ui_allow_wan"`
	// Xray.FallbackTag — старый запасной outbound; на странице больше не меняется
	// (резервы теперь в fallbacks.json), но сохраняется, чтобы не пропал.
	Xray struct {
		FallbackTag string `json:"fallback_tag"`
	} `json:"xray"`
	Watch struct {
		Enabled            bool     `json:"enabled"`
		IntervalSec        int      `json:"interval_sec"`
		FailsToSwitch      int      `json:"fails_to_switch"`
		BackgroundCycleMin int      `json:"background_cycle_min"`
		SwitchFasterMs     int      `json:"switch_faster_ms"`
		TestBytes          int64    `json:"test_bytes"`
		CheckURLs          []string `json:"check_urls"`
		RestartXray        bool     `json:"restart_xray"`
	} `json:"watchdog"`
	Telegram TelegramConfig `json:"telegram"`
}

const secretMask = "••••••"

var telegramTokenRe = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{20,}$`)

// uiSettings — текущие значения для страницы (пароль не отдаётся, токен скрыт).
func (a *App) uiSettings() map[string]any {
	c := a.c
	var s UISettings
	s.SubIntervalHours, s.UserAgent, s.MaxNodes, s.LogFile, s.UIAllowWAN = c.SubIntervalHours, c.UserAgent, c.MaxNodes, c.LogFile, c.UIAllowWAN
	s.Xray.FallbackTag = c.Xray.FallbackTag
	s.Watch.Enabled, s.Watch.IntervalSec, s.Watch.FailsToSwitch = c.Watch.Enabled, c.Watch.IntervalSec, c.Watch.FailsToSwitch
	s.Watch.BackgroundCycleMin, s.Watch.CheckURLs, s.Watch.RestartXray = c.Watch.BackgroundCycleMin, c.Watch.CheckURLs, c.Watch.RestartXray
	s.Watch.TestBytes, s.Watch.SwitchFasterMs = c.Watch.TestBytes, c.Watch.SwitchFasterMs
	s.Telegram = c.Telegram
	if s.Telegram.Token != "" {
		s.Telegram.Token = secretMask
	}
	return map[string]any{"settings": s}
}

func (a *App) saveSettings(s UISettings) error {
	if err := a.validateSettings(&s); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeStateFile(a.c.path(settingsFile), b); err != nil {
		return err
	}
	lg.Printf("настройки сохранены — перезапускаю xsub")
	a.w.saveStats()
	restartSelf()
	return nil
}

// validateSettings проверяет значения и подставляет то, что не меняли (пароль, скрытый токен).
func (a *App) validateSettings(s *UISettings) error {
	c := a.c
	s.Xray.FallbackTag = c.Xray.FallbackTag
	if s.Password == "" {
		s.Password = c.Password
	} else if len(s.Password) < 6 {
		return fmt.Errorf("пароль — не короче 6 символов")
	}
	if s.Telegram.Token == secretMask {
		s.Telegram.Token = c.Telegram.Token
	}
	s.Telegram.Token = strings.TrimSpace(s.Telegram.Token)
	s.Telegram.ChatID = strings.TrimSpace(s.Telegram.ChatID)
	if s.Telegram.Token != "" && !telegramTokenRe.MatchString(s.Telegram.Token) {
		return fmt.Errorf("токен бота выглядит неправильно (формат 123456:ABC…)")
	}
	if s.SubIntervalHours < 1 || s.SubIntervalHours > 168 {
		return fmt.Errorf("интервал обновления подписок — от 1 до 168 часов")
	}
	if s.Watch.IntervalSec < 15 || s.Watch.IntervalSec > 3600 {
		return fmt.Errorf("интервал проверки — от 15 до 3600 секунд")
	}
	if s.Watch.FailsToSwitch < 1 || s.Watch.FailsToSwitch > 10 {
		return fmt.Errorf("число неудач до переключения — от 1 до 10")
	}
	if s.Watch.BackgroundCycleMin != 0 && (s.Watch.BackgroundCycleMin < 5 || s.Watch.BackgroundCycleMin > 1440) {
		return fmt.Errorf("фоновая проверка — 0 (выключена) или от 5 до 1440 минут")
	}
	if s.Watch.TestBytes < 8<<10 || s.Watch.TestBytes > 1<<20 {
		return fmt.Errorf("размер проверочной загрузки — от 8 до 1024 КБ")
	}
	if s.Watch.SwitchFasterMs != 0 && (s.Watch.SwitchFasterMs < 50 || s.Watch.SwitchFasterMs > 10000) {
		return fmt.Errorf("переход на быстрый узел — 0 (выключено) или от 50 до 10000 мс")
	}
	if s.MaxNodes < 1 || s.MaxNodes > 500 {
		return fmt.Errorf("узлов из подписки — от 1 до 500")
	}
	var urls []string
	for _, u := range s.Watch.CheckURLs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if p, err := url.Parse(u); err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return fmt.Errorf("адрес проверки %q — нужна ссылка http(s)://…", u)
		}
		urls = append(urls, u)
	}
	s.Watch.CheckURLs = urls
	if s.LogFile != "" && !filepath.IsAbs(s.LogFile) {
		return fmt.Errorf("путь к журналу должен быть полным (например, /tmp/xsub.log)")
	}
	return nil
}

// restartSelf перезапускает xsub тем же процессом (PID не меняется — скрипт автозапуска не путается).
func restartSelf() {
	go func() {
		time.Sleep(700 * time.Millisecond)
		exe, err := os.Executable()
		if err != nil {
			lg.Printf("не удалось перезапустить xsub: %v", err)
			return
		}
		if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
			lg.Printf("не удалось перезапустить xsub: %v", err)
		}
	}()
}

// ---------- резервная копия ----------

var backupNameRe = regexp.MustCompile(`^(config\.json|settings\.json|subscriptions\.json|groups\.json|routing\.json|vpn\.txt|direct\.txt|fallbacks\.json|group-g[0-9]{1,3}\.txt)$`)

type Backup struct {
	App     string            `json:"app"`
	Version string            `json:"version"`
	Created time.Time         `json:"created"`
	Files   map[string]string `json:"files"`
}

func (a *App) backup() Backup {
	bk := Backup{App: "xsub", Version: version, Created: time.Now(), Files: map[string]string{}}
	entries, _ := os.ReadDir(a.c.dir)
	for _, e := range entries {
		if e.IsDir() || !backupNameRe.MatchString(e.Name()) {
			continue
		}
		if b, err := os.ReadFile(a.c.path(e.Name())); err == nil {
			bk.Files[e.Name()] = string(b)
		}
	}
	return bk
}

func (a *App) restore(bk Backup) error {
	if err := a.restoreFilesOnly(bk); err != nil {
		return err
	}
	lg.Printf("настройки восстановлены из копии от %s — перезапускаю xsub", bk.Created.Format("02.01.2006 15:04"))
	a.w.saveStats()
	restartSelf()
	return nil
}

func (a *App) restoreFilesOnly(bk Backup) error {
	if bk.App != "xsub" || len(bk.Files) == 0 {
		return fmt.Errorf("это не резервная копия xsub")
	}
	if _, ok := bk.Files["config.json"]; !ok {
		return fmt.Errorf("в копии нет config.json")
	}
	for name, content := range bk.Files {
		if !backupNameRe.MatchString(name) {
			return fmt.Errorf("в копии лишний файл %q", name)
		}
		if strings.HasSuffix(name, ".json") {
			var v any
			if err := json.Unmarshal(stripJSONComments([]byte(content)), &v); err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
		}
	}
	// проверяем, что из копии получится рабочий конфиг
	tmp, err := os.MkdirTemp("", "xsub-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for name, content := range bk.Files {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0o600); err != nil {
			return err
		}
	}
	tc, err := loadConfig(filepath.Join(tmp, "config.json"))
	if err != nil {
		return err
	}
	if _, err := loadSubs(tc); err != nil {
		return err
	}
	if _, err := loadGroups(tc); err != nil {
		return err
	}
	if _, err := loadFallbacks(tc); err != nil {
		return err
	}
	// старые списки групп убираем, чтобы не осталось лишних
	if entries, err := os.ReadDir(a.c.dir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "group-") && backupNameRe.MatchString(e.Name()) {
				if _, keep := bk.Files[e.Name()]; !keep {
					_ = os.Remove(a.c.path(e.Name()))
				}
			}
		}
	}
	for _, name := range []string{"settings.json", "groups.json", fallbacksFile, routeDefFile} {
		if _, ok := bk.Files[name]; !ok {
			_ = os.Remove(a.c.path(name))
		}
	}
	for name, content := range bk.Files {
		if err := writeStateFile(a.c.path(name), []byte(content)); err != nil {
			return err
		}
	}
	return nil
}
