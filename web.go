package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var indexHTML []byte

type errString string

func (e errString) Error() string { return string(e) }

func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	get := func(path string, h func(w http.ResponseWriter, r *http.Request)) { mux.HandleFunc("GET "+path, h) }
	post := func(path string, h func(w http.ResponseWriter, r *http.Request)) { mux.HandleFunc("POST "+path, h) }
	body := func(r *http.Request, v any) error {
		return json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(v)
	}

	get("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(indexHTML)
	})
	get("/api/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.status()) })

	// списки: vpn, direct, id группы
	get("/api/list", func(w http.ResponseWriter, r *http.Request) {
		file, err := a.listFile(r.URL.Query().Get("name"))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		b, _ := os.ReadFile(a.c.path(file))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	})
	post("/api/list", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		result(w, a.saveList(r.Context(), r.URL.Query().Get("name"), string(b)))
	})

	// узлы
	post("/api/select", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Target, Tag string }
		if err := body(r, &req); err != nil {
			result(w, fmt.Errorf("не удалось прочитать запрос: %v", err))
			return
		}
		opMu.Lock()
		defer opMu.Unlock()
		result(w, a.w.pin(req.Target, req.Tag))
	})
	post("/api/auto", func(w http.ResponseWriter, r *http.Request) {
		opMu.Lock()
		defer opMu.Unlock()
		a.w.reselect("автовыбор с веб-страницы")
		result(w, nil)
	})
	post("/api/check", func(w http.ResponseWriter, r *http.Request) {
		opMu.Lock()
		defer opMu.Unlock()
		a.w.checkAll()
		result(w, nil)
	})

	// подписки
	get("/api/subs", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		subs := append([]Subscription{}, a.subs...)
		a.mu.Unlock()
		writeJSON(w, subs)
	})
	post("/api/subs", func(w http.ResponseWriter, r *http.Request) {
		var subs []Subscription
		if err := body(r, &subs); err != nil {
			result(w, err)
			return
		}
		result(w, a.saveSubs(subs))
	})
	// Обновление идёт в фоне: подписки качаются до полутора минут каждая, а запрос
	// не должен висеть. Результат виден в статусе — страница опрашивает его сама.
	post("/api/sub/refresh", func(w http.ResponseWriter, r *http.Request) {
		goSafe("обновлении подписок", func() { a.refreshSubs(context.Background()) })
		writeJSON(w, map[string]any{"ok": true})
	})

	// группы
	post("/api/groups", func(w http.ResponseWriter, r *http.Request) {
		var gs []Group
		if err := body(r, &gs); err != nil {
			result(w, err)
			return
		}
		result(w, a.saveGroups(gs))
	})

	// маршрут по умолчанию: куда идёт трафик вне списков и групп
	get("/api/route-default", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"default": routeDefaultResolved(loadRouteDefault(a.c))})
	})
	post("/api/route-default", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Default string `json:"default"`
		}
		if err := body(r, &req); err != nil {
			result(w, fmt.Errorf("не удалось прочитать запрос: %v", err))
			return
		}
		result(w, a.saveRouteDefault(req.Default))
	})

	// проверка окружения (XKeen, ядро, входы)
	get("/api/diag", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, diagnose(a.c)) })

	// резервные узлы
	get("/api/fallbacks", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.uiFallbacks()) })
	post("/api/fallbacks", func(w http.ResponseWriter, r *http.Request) {
		var fs []Fallback
		if err := body(r, &fs); err != nil {
			result(w, err)
			return
		}
		result(w, a.saveFallbacks(fs))
	})

	// geo и внешние списки
	post("/api/geo/refresh", func(w http.ResponseWriter, r *http.Request) {
		a.updateGeo(r.Context(), true)
		a.mu.Lock()
		e := a.geoErr
		a.mu.Unlock()
		if e != "" {
			result(w, errString(e))
			return
		}
		result(w, nil)
	})

	// куда пойдёт сайт
	get("/api/route", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.checkTarget(r.URL.Query().Get("q")))
	})

	// настройки, резервная копия, обновление, Telegram
	get("/api/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.uiSettings()) })
	post("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		var s UISettings
		if err := body(r, &s); err != nil {
			result(w, err)
			return
		}
		result(w, a.saveSettings(s))
	})
	get("/api/backup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="xsub-backup-%s.json"`, time.Now().Format("2006-01-02")))
		writeJSON(w, a.backup())
	})
	post("/api/restore", func(w http.ResponseWriter, r *http.Request) {
		var bk Backup
		if err := body(r, &bk); err != nil {
			result(w, fmt.Errorf("не удалось прочитать файл: %v", err))
			return
		}
		result(w, a.restore(bk))
	})
	post("/api/telegram/test", func(w http.ResponseWriter, r *http.Request) { result(w, a.n.test()) })
	post("/api/update/check", func(w http.ResponseWriter, r *http.Request) {
		a.checkUpdate(r.Context())
		a.mu.Lock()
		l := a.latest
		a.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true, "latest": l, "newer": newerVersion(version, l)})
	})
	post("/api/update", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		l := a.latest
		a.mu.Unlock()
		if l == "" {
			a.checkUpdate(r.Context())
			a.mu.Lock()
			l = a.latest
			a.mu.Unlock()
		}
		if l == "" {
			result(w, errString("не удалось узнать последнюю версию на GitHub — попробуйте позже"))
			return
		}
		if !newerVersion(version, l) {
			result(w, errString("новой версии нет — установлена последняя ("+version+")"))
			return
		}
		result(w, a.startUpgrade())
	})
	get("/api/update/log", func(w http.ResponseWriter, r *http.Request) {
		b, _ := os.ReadFile(updateLog)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	})
	return a.guard(mux)
}

// ---------- доступ ----------

// privateNet — домашняя сеть, VPN-клиенты Keenetic (100.64/10) и сам роутер.
var privateNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
		"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"} {
		_, n, _ := net.ParseCIDR(s)
		out = append(out, n)
	}
	return out
}()

func isPrivate(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

var authLimit = &limiter{fails: map[string][]time.Time{}}

const (
	maxFails   = 10
	failWindow = 10 * time.Minute
)

func (l *limiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	var recent []time.Time
	for _, t := range l.fails[ip] {
		if time.Since(t) < failWindow {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(l.fails, ip) // иначе карта копит по записи на каждый обращавшийся адрес
	} else {
		l.fails[ip] = recent
	}
	return len(recent) >= maxFails
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	l.fails[ip] = append(l.fails[ip], time.Now())
	n := len(l.fails[ip])
	l.mu.Unlock()
	if n == maxFails {
		lg.Printf("вход на страницу: %d неверных паролей с %s — вход с этого адреса закрыт на 10 минут", maxFails, ip)
	}
}

func (l *limiter) ok(ip string) {
	l.mu.Lock()
	delete(l.fails, ip)
	l.mu.Unlock()
}

// sameHost — в заголовке Host адрес самого роутера, а не чужое имя, которое
// в момент запроса указывает на него (DNS rebinding). Пускаем IP-адрес,
// localhost и имена роутера; остальное отклоняем.
func sameHost(c *Config, r *http.Request) bool {
	h := r.Host
	if v, _, err := net.SplitHostPort(h); err == nil {
		h = v
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	switch h {
	case "", "localhost", "my.keenetic.net", "keenetic.net":
		return true
	}
	if strings.HasSuffix(h, ".lan") || strings.HasSuffix(h, ".local") {
		return true
	}
	for _, a := range c.UIAllowHosts {
		if strings.EqualFold(strings.TrimSpace(a), h) {
			return true
		}
	}
	return net.ParseIP(h) != nil
}

// guard: только домашняя сеть (если не разрешено иное), свой Host, защита от подбора
// пароля, Basic-авторизация; изменения — только POST с заголовком X-XSub (чужой сайт не подделает).
func (a *App) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameHost(a.c, r) {
			http.Error(w, "неизвестное имя в заголовке Host — открывайте страницу по адресу роутера или добавьте имя в ui_allow_hosts", http.StatusMisdirectedRequest)
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if !a.c.UIAllowWAN && (ip == nil || !isPrivate(ip)) {
			http.Error(w, "доступ к xsub открыт только из домашней сети (ui_allow_wan в настройках)", http.StatusForbidden)
			return
		}
		if authLimit.blocked(host) {
			http.Error(w, "слишком много неверных паролей — попробуйте через 10 минут", http.StatusTooManyRequests)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(a.c.User)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(a.c.Password)) != 1 {
			if ok {
				authLimit.fail(host)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="xsub", charset="UTF-8"`)
			http.Error(w, "нужен пароль", http.StatusUnauthorized)
			return
		}
		authLimit.ok(host)
		if r.Method == http.MethodPost && r.Header.Get("X-XSub") != "1" {
			http.Error(w, "запрос отклонён", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Страница целиком инлайновая и никуда не ходит, кроме своего же API.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	b, _ := marshal(v)
	w.Write(b)
}

func result(w http.ResponseWriter, err error) {
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(422)
		b, _ := marshal(map[string]any{"ok": false, "error": err.Error()})
		w.Write(b)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
