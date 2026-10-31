package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct {
	Listen   string `json:"listen"`
	User     string `json:"user"`
	Password string `json:"password"`
	LogFile  string `json:"log_file"`   // "" — журнал только в памяти (на веб-странице)
	LogMaxKB int    `json:"log_max_kb"` // размер файла журнала до ротации

	SubIntervalHours int    `json:"sub_interval_hours"`
	MaxNodes         int    `json:"max_nodes"` // на одну подписку
	UserAgent        string `json:"user_agent"`

	// Старый формат (одна подписка в config.json) — переносится в subscriptions.json.
	Legacy *Subscription `json:"subscription,omitempty"`

	UIAllowWAN bool `json:"ui_allow_wan"` // пускать на страницу не только из домашней сети
	// Имена, по которым разрешено открывать страницу, если своё не из обычных
	// (IP-адрес, localhost, *.lan, *.local, имена роутера). Защита от DNS rebinding.
	UIAllowHosts []string `json:"ui_allow_hosts"`
	UpdateRepo   string   `json:"update_repo"` // откуда проверять новые версии (владелец/репозиторий)

	Xray     XrayConfig     `json:"xray"`
	Watch    WatchConfig    `json:"watchdog"`
	Geo      GeoConfig      `json:"geo"`
	Telegram TelegramConfig `json:"telegram"`

	dir string // папка конфига: там же списки, подписки, кэш, бэкапы
}

type Subscription struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent,omitempty"`
	Exclude   string `json:"exclude,omitempty"` // регулярное выражение по имени узла
	Include   string `json:"include,omitempty"` // если задано — брать только совпавшие
	// только для чтения старого формата
	IntervalHours int `json:"interval_hours,omitempty"`
}

type XrayConfig struct {
	Bin                string   `json:"bin"`
	ConfDir            string   `json:"confdir"`
	AssetDir           string   `json:"assetdir"`
	RestartCmd         string   `json:"restart_cmd"`
	ManageAPI          bool     `json:"manage_api"`
	APIListen          string   `json:"api_listen"`
	ProbePort          int      `json:"probe_port"`
	TestPortBase       int      `json:"test_port_base"`
	Balancer           string   `json:"balancer"`
	FallbackTag        string   `json:"fallback_tag"`
	TemplateTag        string   `json:"template_tag"`
	DirectTag          string   `json:"direct_tag"`
	ForceProxyInbounds []string `json:"force_proxy_inbounds"`
	ObservatoryURL     string   `json:"observatory_url"`
	ObservatoryEvery   string   `json:"observatory_interval"`
}

type WatchConfig struct {
	Enabled        bool     `json:"enabled"`
	IntervalSec    int      `json:"interval_sec"`
	TestURL        string   `json:"test_url"`   // {bytes} заменяется на test_bytes
	TestBytes      int64    `json:"test_bytes"` // сколько должно скачаться, чтобы узел считался рабочим
	TimeoutSec     int      `json:"timeout_sec"`
	FailsToSwitch  int      `json:"fails_to_switch"`
	MaxTry         int      `json:"max_try"`
	BadCooldownMin int      `json:"bad_cooldown_min"`
	LatencyURL     string   `json:"latency_url"`
	DirectURLs     []string `json:"direct_urls"`
	// Адреса, которые тоже должны открываться через узел (например, нужный заблокированный сайт).
	CheckURLs []string `json:"check_urls"`
	// Каждый запасной узел проверяется загрузкой раз в столько минут (0 — не проверять).
	// Проверки равномерно распределяются по времени.
	BackgroundCycleMin int `json:"background_cycle_min"`
	// Перейти на запасной узел, если он прошёл проверку, надёжен не хуже текущего
	// и быстрее его на столько миллисекунд (0 — не переходить ради скорости).
	// Работает только вместе с фоновой проверкой: задержки берутся оттуда.
	SwitchFasterMs int `json:"switch_faster_ms"`
	// Куда класть историю проверок, чтобы она пережила перезапуск xsub. По умолчанию
	// в /tmp — это оперативная память роутера: флеш не изнашивается, но сохранение
	// настроек и самообновление больше не обнуляют статистику ("" — не сохранять).
	StatsFile string `json:"stats_file"`
	// Пауза после обнаружения запущенного Xray, прежде чем закрепить узлы (секунды).
	// Даёт Xray время поднять все inbound'ы после перезапуска.
	RestartDelaySec int `json:"restart_delay_sec"`
	// Запускать XKeen заново, если ядро Xray пропало (и не запущен mihomo).
	RestartXray bool `json:"restart_xray"`
}

type TelegramConfig struct {
	Token      string `json:"token"`
	ChatID     string `json:"chat_id"`
	ExpireDays int    `json:"expire_days"` // предупреждать, когда до конца подписки осталось столько дней
	TrafficPct int    `json:"traffic_pct"` // …и когда израсходовано столько процентов трафика
	OnSwitch   bool   `json:"on_switch"`   // сообщать о каждом переключении узла
	OnUpdate   bool   `json:"on_update"`   // сообщать о новой версии xsub
}

type GeoFile struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type GeoConfig struct {
	Files         []GeoFile `json:"files"`
	IntervalHours int       `json:"interval_hours"`
}

func defaultConfig() *Config {
	return &Config{
		Listen:           "0.0.0.0:8099",
		User:             "admin",
		LogFile:          "/tmp/xsub.log", // /tmp — оперативная память
		LogMaxKB:         256,
		SubIntervalHours: 6,
		MaxNodes:         60,
		UserAgent:        "v2rayN/7.0",
		Xray: XrayConfig{
			Bin:                "/opt/sbin/xray",
			ConfDir:            "/opt/etc/xray/configs",
			AssetDir:           "/opt/etc/xray/dat",
			RestartCmd:         "xkeen -restart",
			ManageAPI:          true,
			APIListen:          "127.0.0.1:10085",
			ProbePort:          10990,
			TestPortBase:       11000,
			Balancer:           "xsub",
			DirectTag:          "direct",
			ForceProxyInbounds: []string{"force-proxy-redirect", "force-proxy-tproxy"},
			ObservatoryURL:     "https://www.gstatic.com/generate_204",
			ObservatoryEvery:   "2m",
		},
		Watch: WatchConfig{
			Enabled:            true,
			IntervalSec:        60,
			TestURL:            "https://speed.cloudflare.com/__down?bytes={bytes}",
			TestBytes:          32 << 10, // известная блокировка срабатывает на 16–20 КБ
			TimeoutSec:         10,
			FailsToSwitch:      2,
			MaxTry:             20,
			BadCooldownMin:     30,
			LatencyURL:         "https://www.gstatic.com/generate_204",
			DirectURLs:         []string{"https://ya.ru", "https://www.google.com", "https://1.1.1.1"},
			BackgroundCycleMin: 30,
			SwitchFasterMs:     200,
			StatsFile:          "/tmp/xsub-stats.json",
			RestartDelaySec:    7,
			RestartXray:        true,
		},
		Telegram:   TelegramConfig{ExpireDays: 3, TrafficPct: 90, OnSwitch: true, OnUpdate: true},
		UpdateRepo: defaultRepo,
		Geo: GeoConfig{
			IntervalHours: 24,
			Files: []GeoFile{
				{Name: "geosite_itdog.dat", URL: "https://github.com/itdoginfo/allow-domains/releases/latest/download/geosite.dat"},
			},
		},
	}
}

// serverConfigTune применяет дефолты серверного режима (Docker) к загруженному
// конфигу: то, что админ не задал явно в config.json, должно работать из коробки.
func serverConfigTune(c *Config) {
	if !serverMode {
		return
	}
	if c.Xray.Bin == "" || c.Xray.Bin == "/opt/sbin/xray" {
		c.Xray.Bin = "/usr/local/bin/xray"
	}
	if c.Xray.ConfDir == "" || c.Xray.ConfDir == "/opt/etc/xray/configs" {
		c.Xray.ConfDir = "/data/xray"
	}
	if c.Xray.AssetDir == "" || c.Xray.AssetDir == "/opt/etc/xray/dat" {
		c.Xray.AssetDir = "/data/xray"
	}
	if c.Xray.RestartCmd == "" || c.Xray.RestartCmd == "xkeen -restart" {
		c.Xray.RestartCmd = "/usr/local/bin/xsub-xray-restart"
	}
	if len(c.Xray.ForceProxyInbounds) == 2 && c.Xray.ForceProxyInbounds[0] == "force-proxy-redirect" {
		// В серверном режиме маршрут вне списков задаёт переключатель «По умолчанию»
		// (routing.json), а безусловный force нужен только политикам XKeen.
		c.Xray.ForceProxyInbounds = nil
	}
	if c.LogFile == "/tmp/xsub.log" {
		c.LogFile = "" // журнал — в stdout (docker logs)
	}
	if c.Watch.StatsFile == "/tmp/xsub-stats.json" {
		// /tmp контейнера не переживает его пересоздание: история проверок хранится
		// рядом с config.json (пустое значение loadConfig заменит на путь в data).
		c.Watch.StatsFile = ""
	}
}

// ---------- файлы состояния (подписки, группы, резервы, настройки страницы) ----------

// readStateFile читает json-файл состояния (комментарии // и /* */ допускаются).
// Если основной файл повреждён, подхватывает .bak-копию: битый файл не должен
// лишать xsub запуска — на роутере некому поднять упавший демон, а сторож
// обязан продолжать работать.
func readStateFile(path string, v any) (usedBackup bool, err error) {
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		return false, rerr
	}
	perr := json.Unmarshal(stripJSONComments(b), v)
	if perr == nil {
		return false, nil
	}
	bb, berr := os.ReadFile(path + ".bak")
	if berr != nil {
		return false, fmt.Errorf("%s: %v", path, perr)
	}
	if json.Unmarshal(stripJSONComments(bb), v) != nil {
		return false, fmt.Errorf("%s и .bak-копия не читаются: %v", path, perr)
	}
	return true, nil
}

// writeStateFile пишет файл состояния атомарно и обновляет рядом .bak-копию.
// Файлы маленькие и пишутся только действиями пользователя, двойная запись
// не изнашивает накопитель.
func writeStateFile(path string, b []byte) error {
	if err := writeAtomicMode(path, b, 0o600); err != nil {
		return err
	}
	return writeAtomicMode(path+".bak", b, 0o600)
}

func loadConfig(path string) (*Config, error) {
	c := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(stripJSONComments(b), c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.dir = filepath.Dir(path)
	// settings.json — то, что поменяли на веб-странице; поверх config.json.
	// Не читается — не повод умирать: продолжаем с config.json, следующее
	// сохранение настроек всё равно перезапишет файл заново.
	if sb, err := os.ReadFile(c.path(settingsFile)); err == nil {
		if err := json.Unmarshal(sb, c); err != nil {
			var ok bool
			if bb, berr := os.ReadFile(c.path(settingsFile) + ".bak"); berr == nil {
				ok = json.Unmarshal(bb, c) == nil
			}
			if ok {
				fmt.Fprintf(os.Stderr, "xsub: %s повреждён — поднята .bak-копия\n", settingsFile)
			} else {
				fmt.Fprintf(os.Stderr, "xsub: %s не читается (%v) — настройки страницы проигнорированы\n", settingsFile, err)
			}
		}
	}
	if c.Password == "" {
		return nil, fmt.Errorf("%s: задайте password для веб-страницы", path)
	}
	// Серверный режим: роутерные дефолты, оставшиеся после наложения файлов,
	// заменяем серверными; пустой stats_file получает путь рядом с config.json.
	serverConfigTune(c)
	if serverMode && c.Watch.StatsFile == "" {
		c.Watch.StatsFile = c.path("xsub-stats.json")
	}
	if c.Watch.IntervalSec < 15 {
		c.Watch.IntervalSec = 15
	}
	if c.Legacy != nil && c.Legacy.IntervalHours > 0 {
		c.SubIntervalHours = c.Legacy.IntervalHours
	}
	if c.SubIntervalHours < 1 {
		c.SubIntervalHours = 1
	}
	if c.LogMaxKB < 16 {
		c.LogMaxKB = 16
	}
	if c.Geo.IntervalHours < 1 {
		c.Geo.IntervalHours = 24
	}
	if c.Watch.TestBytes < 1024 {
		c.Watch.TestBytes = 32 << 10
	}
	if c.Watch.TimeoutSec < 3 {
		c.Watch.TimeoutSec = 10
	}
	if c.Watch.FailsToSwitch < 1 {
		c.Watch.FailsToSwitch = 1
	}
	if c.Watch.MaxTry < 1 {
		c.Watch.MaxTry = 20
	}
	if c.Watch.SwitchFasterMs < 0 {
		c.Watch.SwitchFasterMs = 0
	}
	if c.Watch.RestartDelaySec < 1 {
		c.Watch.RestartDelaySec = 7
	}
	if c.Xray.Balancer == "" {
		c.Xray.Balancer = "xsub"
	}
	return c, nil
}

func (c *Config) path(name string) string { return filepath.Join(c.dir, name) }

const (
	subsFile     = "subscriptions.json"
	settingsFile = "settings.json"
)

// loadSubs читает subscriptions.json; при его отсутствии переносит подписку из старого config.json.
func loadSubs(c *Config) ([]Subscription, error) {
	_, ferr := os.ReadFile(c.path(subsFile))
	if os.IsNotExist(ferr) {
		if c.Legacy != nil && strings.HasPrefix(c.Legacy.URL, "http") {
			s := *c.Legacy
			s.IntervalHours = 0
			if s.Name == "" {
				s.Name = "Подписка"
			}
			subs := []Subscription{s}
			if err := saveSubsFile(c, subs); err != nil {
				return nil, err
			}
			lg.Printf("подписка из config.json перенесена в %s", subsFile)
			return subs, nil
		}
		return nil, nil
	}
	if ferr != nil {
		return nil, ferr
	}
	var subs []Subscription
	usedBackup, serr := readStateFile(c.path(subsFile), &subs)
	if serr != nil {
		return nil, serr
	}
	if usedBackup {
		lg.Printf("%s повреждён — поднята .bak-копия", subsFile)
	}
	return subs, validateSubs(subs)
}

func validateSubs(subs []Subscription) error {
	seen := map[string]bool{}
	for i, s := range subs {
		n := s.Name
		if n == "" {
			n = fmt.Sprintf("№%d", i+1)
		}
		if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
			return fmt.Errorf("подписка %s: ссылка должна начинаться с http:// или https://", n)
		}
		if seen[s.URL] {
			return fmt.Errorf("подписка %s: такая ссылка уже есть", n)
		}
		seen[s.URL] = true
		for _, re := range []string{s.Exclude, s.Include} {
			if re == "" {
				continue
			}
			if _, err := regexp.Compile(re); err != nil {
				return fmt.Errorf("подписка %s: ошибка в фильтре %q: %v", n, re, err)
			}
		}
	}
	return nil
}

func saveSubsFile(c *Config, subs []Subscription) error {
	if subs == nil {
		subs = []Subscription{}
	}
	b, err := marshal(subs)
	if err != nil {
		return err
	}
	return writeStateFile(c.path(subsFile), b)
}

// stripJSONComments убирает // и /* */ вне строк (XKeen хранит конфиги с комментариями).
func stripJSONComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if inStr {
			out = append(out, ch)
			if esc {
				esc = false
			} else if ch == '\\' {
				esc = true
			} else if ch == '"' {
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
			out = append(out, ch)
			continue
		}
		if ch == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
			continue
		}
		if ch == '/' && i+1 < len(b) && b[i+1] == '*' {
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, ch)
	}
	return out
}
