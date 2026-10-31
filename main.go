package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	version     = "dev"
	defaultRepo = "furriest/xsub" // при сборке: -X main.defaultRepo=владелец/репозиторий
)

// serverMode — серверный режим (Docker на x86_64/arm64): свои пути и дефолты,
// журнал в stdout, обновление — новым образом контейнера, а не opkg.
// Включается переменной XSUB_SERVER=1; если она не задана — определяется
// по /.dockerenv и /run/.containerenv, чтобы образ работал без явных настроек.
var serverMode = detectServerMode()

func detectServerMode() bool {
	switch strings.ToLower(os.Getenv("XSUB_SERVER")) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

const defaultVPN = `# Через VPN. Одна запись на строку, комментарии после #.
#   example.com            — домен со всеми поддоменами
#   =example.com           — только этот домен
#   ext:файл.dat:категория — категория из файла в папке geo-файлов Xray
#   geosite:категория      — категория из geosite.dat
#   1.2.3.0/24             — IP или подсеть
#
# Готовые категории itdoginfo/allow-domains (файл geosite_itdog.dat скачивается сам):
# russia-inside — заблокированное в РФ; youtube, telegram, discord, meta, twitter, tiktok …
ext:geosite_itdog.dat:russia-inside
ext:geosite_itdog.dat:telegram

# Подсети Telegram (https://core.telegram.org/resources/cidr.txt)
91.108.4.0/22
91.108.8.0/22
91.108.12.0/22
91.108.16.0/22
91.108.20.0/22
91.108.56.0/22
91.105.192.0/23
95.161.64.0/20
149.154.160.0/20
185.76.151.0/24
`

const defaultVPNServer = `# Через VPN. Одна запись на строку, формат как в README на GitHub.
# В серверном режиме весь трафик SOCKS5-входа идёт через VPN принудительно
# (см. force_proxy_inbounds в config.json) — этот список нужен, только если
# принудительную маршрутизацию отключить.
google.com
youtube.com
`

const defaultDirect = `# Напрямую. Проверяется раньше списка «Через VPN» — сюда исключения.
# Формат тот же, что в vpn.txt.
`

const defaultConfigJSON = `{
  // Веб-страница xsub: http://<IP-роутера>:8099/
  "listen": "0.0.0.0:8099",
  "user": "admin",
  "password": "%s",

  // Журнал: /tmp — оперативная память (не изнашивает флеш), "" — только на веб-странице.
  // Чтобы журнал переживал перезагрузку: "/opt/var/log/xsub.log".
  "log_file": "/tmp/xsub.log",

  // Подписки добавляются на веб-странице (хранятся в subscriptions.json).
  "sub_interval_hours": 6,
  // Панели отдают разный формат в зависимости от клиента. xsub понимает ссылки
  // (vless, vmess, trojan, ss, hysteria2, wireguard, socks, http), Clash YAML,
  // sing-box JSON и JSON Xray; у каждой подписки можно задать свой User-Agent.
  "user_agent": "v2rayN/7.0",

  "xray": {
    "bin": "/opt/sbin/xray",
    "confdir": "/opt/etc/xray/configs",
    "assetdir": "/opt/etc/xray/dat",
    "restart_cmd": "xkeen -restart",
    // Запасной outbound из ваших конфигов — на случай, если не работает ни один узел подписок.
    "fallback_tag": ""
  },

  "watchdog": {
    "enabled": true,
    "interval_sec": 60,
    "fails_to_switch": 2
  }
}
`

// defaultConfigJSONServer — конфиг для -init в серверном режиме. Пути к ядру,
// confdir, restart_cmd и force_proxy_inbounds берутся из дефолтов серверного
// режима и сюда не дублируются: менять их в файле не нужно.
const defaultConfigJSONServer = `{
  // Веб-страница xsub: http://<адрес сервера>:8099/
  // Из коробки страница открывается только с частных адресов (LAN, SSH-туннель).
  // Доступ из интернета — включите ui_allow_wan в настройках (логин и пароль обязательны).
  "listen": "0.0.0.0:8099",
  "user": "admin",
  "password": "%s",

  // Журнал: "" — stdout (читает docker logs); путь — файл.
  "log_file": "",

  // Подписки добавляются на веб-странице (хранятся в subscriptions.json).
  "sub_interval_hours": 6,
  // Панели отдают разный формат в зависимости от клиента. xsub понимает ссылки
  // (vless, vmess, trojan, ss, hysteria2, wireguard, socks, http), Clash YAML,
  // sing-box JSON и JSON Xray; у каждой подписки можно задать свой User-Agent.
  "user_agent": "v2rayN/7.0",

  "xray": {
    // bin, confdir, restart_cmd и force_proxy_inbounds заданы дефолтами
    // серверного режима — в этом файле их менять не нужно.
    // SOCKS5-вход in-socks (тег из force_proxy_inbounds) создаёт entrypoint
    // контейнера: docker/xsub-entrypoint собирает confdir/01_inbounds.json
    // из переменных SOCKS_PORT, SOCKS_USER и SOCKS_PASSWORD.
    // Запасной outbound из ваших конфигов — на случай, если не работает ни один узел подписок.
    "fallback_tag": ""
  },

  "watchdog": {
    "enabled": true,
    "interval_sec": 60,
    "fails_to_switch": 2
  }
}
`

func randomPassword(n int) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			// Без надёжной случайности пароль придумывать нельзя.
			fmt.Fprintln(os.Stderr, "xsub: нет источника случайных чисел:", err)
			os.Exit(1)
		}
		b.WriteByte(alphabet[k.Int64()])
	}
	return b.String()
}

func doInit(cfgPath string) int {
	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Println("ошибка:", err)
		return 1
	}
	cfgTmpl, vpn := defaultConfigJSON, defaultVPN
	if serverMode {
		cfgTmpl, vpn = defaultConfigJSONServer, defaultVPNServer
	}
	pw := ""
	files := []struct {
		path, content string
	}{
		{cfgPath, ""},
		{filepath.Join(dir, "vpn.txt"), vpn},
		{filepath.Join(dir, "direct.txt"), defaultDirect},
	}
	for _, f := range files {
		if _, err := os.Stat(f.path); err == nil {
			continue
		}
		content := f.content
		if f.path == cfgPath {
			pw = randomPassword(12)
			content = fmt.Sprintf(cfgTmpl, pw)
		}
		if err := os.WriteFile(f.path, []byte(content), 0o600); err != nil {
			fmt.Println("ошибка:", err)
			return 1
		}
		fmt.Println("создан:", f.path)
	}
	if pw != "" {
		fmt.Println()
		fmt.Println("Веб-страница: http://<адрес устройства>:8099/")
		fmt.Println("Логин: admin")
		fmt.Println("Пароль:", pw)
		fmt.Println("(пароль можно поменять в", cfgPath+")")
	}
	return 0
}

func main() {
	cfgPath := flag.String("config", "/opt/etc/xsub/config.json", "путь к конфигу")
	initFlag := flag.Bool("init", false, "создать конфиг и списки по умолчанию (существующие файлы не трогает)")
	restore := flag.Bool("restore", false, "вернуть конфиги Xray к состоянию до xsub и перезапустить Xray")
	showVer := flag.Bool("version", false, "показать версию")
	flag.Parse()

	switch {
	case *showVer:
		fmt.Println("xsub", version)
		return
	case *initFlag:
		os.Exit(doInit(*cfgPath))
	}

	c, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xsub:", err)
		os.Exit(1)
	}
	if *restore {
		if err := restoreOriginals(c); err != nil {
			fmt.Fprintln(os.Stderr, "xsub:", err)
			os.Exit(1)
		}
		fmt.Println("конфиги Xray возвращены к состоянию до xsub")
		return
	}

	lg.path, lg.maxSize = c.LogFile, int64(c.LogMaxKB)<<10
	lg.echo = serverMode // в контейнере журнал должен быть виден в docker logs
	if _, err := os.Stat(c.Xray.Bin); err != nil {
		fmt.Fprintln(os.Stderr, "xsub: не найден xray:", c.Xray.Bin)
		os.Exit(1)
	}
	a, err := newApp(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xsub:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	lg.Printf("xsub %s запущен, веб-страница: http://%s/", version, c.Listen)

	// WriteTimeout велик: /api/update/check и проверка Telegram ходят в сеть
	// до трёх минут. Остальные таймауты — против зависших соединений.
	srv := &http.Server{
		Addr:              c.Listen,
		Handler:           a.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      4 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}
	srvErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			srvErr <- err
		}
	}()

	goSafe("запуске", func() {
		safely("начальной настройке", a.startup)
		go a.subLoop(ctx)
		go a.healLoop(ctx)
		go every(ctx, "обновлении geo", time.Duration(c.Geo.IntervalHours)*time.Hour, func() { a.updateGeo(ctx, true) })
		go every(ctx, "сохранении истории проверок", 5*time.Minute, a.w.saveStats)
		goSafe("проверке обновлений", func() {
			time.Sleep(2 * time.Minute)
			safely("проверке обновлений", func() { a.checkUpdate(ctx) })
			every(ctx, "проверке обновлений", 24*time.Hour, func() { a.checkUpdate(ctx) })
		})
		a.w.loop(ctx)
	})

	// Порт занят: процесс без веб-страницы бесполезен, а присмотр из cron его
	// не перезапустит — процесс-то жив. Выходим с ошибкой, cron поднимет заново.
	var listenErr error
	select {
	case <-ctx.Done():
	case listenErr = <-srvErr:
		lg.Printf("веб-страница не запущена: %v", listenErr)
	}
	a.w.saveStats() // до Shutdown: S99xsub stop добивает процесс через секунду
	lg.Printf("xsub остановлен")
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	lg.Close()
	if listenErr != nil {
		// log_file может быть пустым — тогда в журнал ничего не попадёт,
		// а S99xsub при запуске перехватывает stderr в /tmp/xsub.out.
		fmt.Fprintln(os.Stderr, "xsub: веб-страница не запущена — выход:", listenErr)
		os.Exit(1)
	}
}
