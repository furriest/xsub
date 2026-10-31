package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// CheckResult — ответ на «куда пойдёт этот сайт».
type CheckResult struct {
	Input  string   `json:"input"`
	Route  string   `json:"route"`  // direct, vpn, group, none
	Target string   `json:"target"` // «Через VPN», название группы…
	List   string   `json:"list"`   // в каком списке нашлось
	Rule   string   `json:"rule"`   // какой строкой
	Via    string   `json:"via"`    // через какой узел пойдёт сейчас
	Notes  []string `json:"notes"`
}

// normalizeTarget: из ссылки или «host:port» оставляет имя хоста или IP.
func normalizeTarget(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.Trim(s, "[]"), ".")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

// matchDomainRule проверяет домен по правилу в формате Xray (domain:, full:, keyword:, regexp:, geosite:, ext:).
func matchDomainRule(c *Config, d, rule string) (bool, error) {
	low := strings.ToLower(rule)
	switch {
	case strings.HasPrefix(low, "domain:"):
		v := low[len("domain:"):]
		return d == v || strings.HasSuffix(d, "."+v), nil
	case strings.HasPrefix(low, "full:"):
		return d == low[len("full:"):], nil
	case strings.HasPrefix(low, "keyword:"):
		return strings.Contains(d, low[len("keyword:"):]), nil
	case strings.HasPrefix(low, "regexp:"):
		re, err := regexp.Compile(rule[len("regexp:"):])
		if err != nil {
			return false, err
		}
		return re.MatchString(d), nil
	case strings.HasPrefix(low, "geosite:"):
		return matchGeoSite(c, "geosite.dat", rule[len("geosite:"):], d)
	case strings.HasPrefix(low, "ext:"):
		parts := strings.SplitN(rule[len("ext:"):], ":", 2)
		if len(parts) != 2 {
			return false, fmt.Errorf("неверное правило %s", rule)
		}
		return matchGeoSite(c, parts[0], parts[1], d)
	}
	return false, nil
}

func matchGeoSite(c *Config, file, cat, d string) (bool, error) {
	var attr string
	if i := strings.Index(cat, "@"); i >= 0 {
		cat, attr = cat[:i], strings.ToLower(cat[i+1:])
	}
	list, err := geoSite(c, file, cat)
	if err != nil {
		return false, err
	}
	for _, g := range list {
		if attr != "" {
			has := false
			for _, a := range g.attrs {
				if strings.EqualFold(a, attr) {
					has = true
				}
			}
			if !has {
				continue
			}
		}
		v := g.value // уже в нижнем регистре, кроме типа 1 — у него готовое выражение
		switch g.typ {
		case 0:
			if strings.Contains(d, v) {
				return true, nil
			}
		case 1:
			if g.re != nil && g.re.MatchString(d) {
				return true, nil
			}
		case 2:
			if d == v || strings.HasSuffix(d, "."+v) {
				return true, nil
			}
		case 3:
			if d == v {
				return true, nil
			}
		}
	}
	return false, nil
}

func matchIPRule(c *Config, ip net.IP, rule string) (bool, error) {
	low := strings.ToLower(rule)
	if strings.HasPrefix(low, "geoip:") {
		cat := rule[len("geoip:"):]
		neg := strings.HasPrefix(cat, "!")
		cat = strings.TrimPrefix(cat, "!")
		nets, err := geoIP(c, "geoip.dat", cat)
		if err != nil {
			return false, err
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return !neg, nil
			}
		}
		return neg, nil
	}
	if strings.HasPrefix(low, "ext:") {
		parts := strings.SplitN(rule[len("ext:"):], ":", 2)
		if len(parts) == 2 {
			nets, err := geoIP(c, parts[0], parts[1])
			if err != nil {
				return false, err
			}
			for _, n := range nets {
				if n.Contains(ip) {
					return true, nil
				}
			}
		}
		return false, nil
	}
	if _, n, err := net.ParseCIDR(rule); err == nil {
		return n.Contains(ip), nil
	}
	if r := net.ParseIP(rule); r != nil {
		return r.Equal(ip), nil
	}
	return false, nil
}

// matchList ищет первую подходящую строку в файле списка (с учётом внешних списков).
func matchList(c *Config, file, target string) (rule string, notes []string) {
	b, _ := os.ReadFile(c.path(file))
	ip := net.ParseIP(target)
	check := func(kind, v string) (bool, string) {
		var ok bool
		var err error
		switch {
		case kind == "domain" && ip == nil:
			ok, err = matchDomainRule(c, target, v)
		case kind == "ip" && ip != nil:
			ok, err = matchIPRule(c, ip, v)
		}
		if err != nil {
			return false, fmt.Sprintf("%s: %v", v, err)
		}
		return ok, ""
	}
	for _, raw := range strings.Split(string(b), "\n") {
		kind, v, err := parseLine(raw)
		if err != nil || kind == "" {
			continue
		}
		if kind == "remote" {
			cached, err := os.ReadFile(remotePath(c, v))
			if err != nil {
				notes = append(notes, "внешний список ещё не скачан: "+v)
				continue
			}
			for _, rr := range strings.Split(string(cached), "\n") {
				k, vv, e := parseLine(strings.TrimSpace(rr))
				if e != nil || k == "" || k == "remote" {
					continue
				}
				if ok, n := check(k, vv); n != "" {
					notes = append(notes, n)
				} else if ok {
					return strings.TrimSpace(raw) + " → " + strings.TrimSpace(rr), notes
				}
			}
			continue
		}
		if ok, n := check(kind, v); n != "" {
			notes = append(notes, n)
		} else if ok {
			return strings.TrimSpace(raw), notes
		}
	}
	return "", notes
}

// checkTarget повторяет порядок правил в 05_routing.json: «Напрямую», группы,
// «Через VPN», дальше — маршрут по умолчанию (переключатель на странице списков).
func (a *App) checkTarget(input string) CheckResult {
	t := normalizeTarget(input)
	res := CheckResult{Input: t}
	if t == "" {
		res.Route = "none"
		res.Notes = append(res.Notes, "введите домен или IP-адрес")
		return res
	}
	via := func(targetID string) string {
		st := a.w.status()
		for _, tg := range st.Targets {
			if tg.ID == targetID {
				if tg.ActiveName != "" {
					return tg.ActiveName
				}
				return "автовыбор Xray"
			}
		}
		if targetID != "" {
			for _, tg := range st.Targets {
				if tg.ID == "" {
					return firstNonEmpty(tg.ActiveName, "автовыбор Xray") + " (в группе нет узлов — через основной)"
				}
			}
		}
		return ""
	}
	if rule, notes := matchList(a.c, "direct.txt", t); rule != "" {
		res.Route, res.Target, res.List, res.Rule, res.Notes = "direct", "Напрямую", "Напрямую (direct.txt)", rule, notes
	} else {
		res.Notes = append(res.Notes, notes...)
		groups, _ := loadGroups(a.c)
		for _, g := range groups {
			if rule, notes := matchList(a.c, groupListName(g.ID), t); rule != "" {
				res.Route, res.Target, res.List, res.Rule, res.Via = "group", g.Name, "Группа «"+g.Name+"»", rule, via(g.ID)
				res.Notes = append(res.Notes, notes...)
				break
			} else {
				res.Notes = append(res.Notes, notes...)
			}
		}
		if res.Route == "" {
			if rule, notes := matchList(a.c, "vpn.txt", t); rule != "" {
				res.Route, res.Target, res.List, res.Rule, res.Via = "vpn", "Через VPN", "Через VPN (vpn.txt)", rule, via("")
				res.Notes = append(res.Notes, notes...)
			} else {
				res.Notes = append(res.Notes, notes...)
				if routeDefaultResolved(loadRouteDefault(a.c)) == "vpn" {
					res.Route, res.Target, res.Via = "vpn", "Через VPN (ни в одном списке)", via("")
					res.Notes = append(res.Notes, "так решил переключатель «По умолчанию» на вкладке «Списки и группы»")
				} else {
					res.Route, res.Target = "direct", "Напрямую (ни в одном списке)"
				}
			}
		}
	}
	if res.Route != "direct" && res.Via == "" {
		res.Notes = append(res.Notes, "узлов нет — трафик пойдёт через запасной outbound или напрямую")
	}
	if net.ParseIP(t) == nil {
		res.Notes = append(res.Notes, "правила по IP-адресам срабатывают, только если программа обращается к сайту по IP, а не по имени")
	}
	res.Notes = append(res.Notes, "если в XKeen включено исключение российских подсетей (xkeen -gips), такие адреса идут напрямую ещё до этих правил")
	return res
}
