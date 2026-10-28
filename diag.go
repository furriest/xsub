package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Проверка окружения: всё ли готово, чтобы xsub работал без ручных правок XKeen и Xray.

var (
	xkeenBin  = "/opt/sbin/xkeen"
	xkeenInit = "/opt/etc/init.d/S05xkeen"
	xkeenDir  = "/opt/etc/xkeen"
)

// DiagItem — одна проверка. Level: ok, info, warn, bad. Fix — что сделать (команда или действие).
type DiagItem struct {
	ID    string `json:"id"`
	Level string `json:"level"`
	Text  string `json:"text"`
	Fix   string `json:"fix,omitempty"`
}

var xrayVerRe = regexp.MustCompile(`Xray (\d+\.\d+\.\d+)`)

func xrayVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := runCmd(ctx, nil, bin, "version")
	if err != nil {
		return ""
	}
	if m := xrayVerRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// shellVar читает переменную вида name="value" из скрипта.
func shellVar(path, name string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `="?([^"\n]*)"?`)
	if m := re.FindSubmatch(b); m != nil {
		return string(m[1]), true
	}
	return "", false
}

func fileHasLines(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			return true
		}
	}
	return false
}

func diagnose(c *Config) []DiagItem {
	var d []DiagItem
	add := func(id, level, text, fix string) { d = append(d, DiagItem{id, level, text, fix}) }

	if _, err := os.Stat(xkeenBin); err != nil {
		add("xkeen", "bad", "XKeen не установлен — без него трафик роутера не попадает в Xray.",
			`opkg update && opkg install curl tar && sh -c "$(curl -sSL https://raw.githubusercontent.com/jameszeroX/XKeen/main/install.sh)"`)
	} else {
		add("xkeen", "ok", "XKeen установлен.", "")
	}

	ver := ""
	if _, err := os.Stat(c.Xray.Bin); err != nil {
		add("xray", "bad", "Не найдено ядро Xray ("+c.Xray.Bin+").", "xkeen -xray")
	} else if ver = xrayVersion(c.Xray.Bin); ver != "" {
		add("xray", "ok", "Ядро Xray "+ver+".", "")
	} else {
		add("xray", "warn", "Xray найден, но не отвечает на «xray version».", "")
	}

	switch {
	case xrayStartTime(c) != "":
		add("core", "ok", "Xray запущен.", "")
	case procStamp("mihomo") != "":
		add("core", "bad", "XKeen работает на ядре mihomo, а xsub управляет только Xray.", "xkeen -xray")
	default:
		add("core", "bad", "Xray не запущен.", "xkeen -start")
	}

	if _, err := os.Stat(xkeenInit); err == nil {
		if v, ok := shellVar(xkeenInit, "start_auto"); ok && v != "on" {
			add("auto", "warn", "Автозапуск XKeen выключен — после перезагрузки роутера VPN не заработает.", "xkeen -auto")
		} else {
			add("auto", "ok", "XKeen запускается вместе с роутером.", "")
		}
	}

	env, err := scanEnv(c)
	if err != nil {
		add("conf", "bad", "Конфиги Xray не читаются: "+err.Error(), "")
		return d
	}
	switch {
	case env.InTags["redirect"] && env.InTags["tproxy"]:
		add("mode", "ok", "Режим XKeen с UDP: TCP и UDP (в том числе QUIC) идут через Xray.", "")
	case env.InTags["tproxy"]:
		add("mode", "ok", "Режим TProxy: TCP и UDP идут через Xray.", "")
	case env.InTags["redirect"]:
		add("mode", "info", "Режим Redirect: через Xray идёт только TCP. UDP (QUIC в YouTube, звонки) пойдёт напрямую — браузеры обычно сами переключаются на TCP.", "")
	default:
		add("mode", "warn", "В конфигах нет входов XKeen (redirect / tproxy) — трафик устройств не попадёт в Xray.", "xkeen -restart")
	}
	for _, tag := range []string{"redirect", "tproxy"} {
		if env.InTags[tag] && !env.Sniff[tag] {
			add("sniff-"+tag, "warn", "У входа «"+tag+"» выключен sniffing — правила по доменам (списки, группы) для него не сработают, только по IP.",
				`в 03_inbounds.json для входа "`+tag+`": "sniffing": {"enabled": true, "routeOnly": true, "destOverride": ["http", "tls", "quic"]}`)
		}
	}

	if b, err := os.ReadFile(filepath.Join(xkeenDir, "xkeen.json")); err == nil {
		var x struct {
			XKeen struct {
				Xray struct {
					SpeedBalancer struct {
						Enabled bool `json:"enabled"`
					} `json:"speed_balancer"`
				} `json:"xray"`
			} `json:"xkeen"`
		}
		if json.Unmarshal(stripJSONComments(b), &x) == nil && x.XKeen.Xray.SpeedBalancer.Enabled {
			add("sb", "warn", "Включён балансировщик XKeen (speed_balancer) — он спорит со сторожем xsub за выбор узла.", "xkeen -sb off")
		}
	}
	if fileHasLines(filepath.Join(xkeenDir, "ipset", "ru_exclude_ipv4.lst")) {
		// Это GeoIPSET самого XKeen: «-gips» ставит списки подсетей, «-dgips» убирает.
		// Запускать их из xsub нельзя: «-dgips» спрашивает подтверждение и без терминала
		// понимает ответ как отказ, а «-gips» качает подсети с GitHub напрямую, мимо VPN.
		add("ru", "info", "XKeen исключает российские IP из проксирования: такие сайты пойдут напрямую, даже если они в списке «Через VPN». Управляется командами XKeen: «xkeen -gips» включить, «xkeen -dgips» выключить.", "")
	}
	return d
}
