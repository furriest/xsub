package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ---------- разбор строк списков ----------

// Rules — правила одного списка в формате Xray.
type Rules struct {
	Domains []string
	IPs     []string
}

func (r *Rules) add(o Rules) {
	r.Domains = append(r.Domains, o.Domains...)
	r.IPs = append(r.IPs, o.IPs...)
}

func (r Rules) empty() bool { return len(r.Domains) == 0 && len(r.IPs) == 0 }

func isRemoteLine(line string) bool {
	l := strings.ToLower(line)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// parseLine переводит одну строку списка в правило Xray. kind: "domain", "ip", "remote" или "" (пусто/ошибка).
func parseLine(raw string) (kind, value string, err error) {
	line := raw
	if j := strings.Index(line, "#"); j >= 0 {
		line = line[:j]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", nil
	}
	if isRemoteLine(line) {
		return "remote", line, nil
	}
	low := strings.ToLower(line)
	switch {
	case strings.HasPrefix(low, "ip:"):
		return "ip", strings.TrimSpace(line[3:]), nil
	case strings.HasPrefix(low, "geoip:"):
		return "ip", low, nil
	case strings.HasPrefix(low, "regexp:"), strings.HasPrefix(low, "ext:"):
		return "domain", line, nil // регистр в regexp и именах файлов важен
	case strings.HasPrefix(low, "geosite:"), strings.HasPrefix(low, "domain:"),
		strings.HasPrefix(low, "full:"), strings.HasPrefix(low, "keyword:"):
		return "domain", low, nil
	case strings.HasPrefix(line, "="):
		d := strings.TrimSpace(low[1:])
		if !validDomain(d) {
			return "", "", fmt.Errorf("%q — не похоже на домен", raw)
		}
		return "domain", "full:" + d, nil
	}
	if _, _, e := net.ParseCIDR(line); e == nil {
		return "ip", line, nil
	}
	if net.ParseIP(line) != nil {
		return "ip", line, nil
	}
	d := strings.TrimPrefix(strings.TrimPrefix(low, "*."), ".")
	if !validDomain(d) {
		return "", "", fmt.Errorf("%q — не похоже на домен", raw)
	}
	return "domain", "domain:" + d, nil
}

// parseListFull разбирает текст списка: правила, ссылки на внешние списки, ошибки по строкам.
func parseListFull(text string) (r Rules, remotes []string, errs []string) {
	for i, raw := range strings.Split(text, "\n") {
		kind, v, err := parseLine(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("строка %d: %v", i+1, err))
			continue
		}
		switch kind {
		case "domain":
			r.Domains = append(r.Domains, v)
		case "ip":
			r.IPs = append(r.IPs, v)
		case "remote":
			remotes = append(remotes, v)
		}
	}
	return
}

func validDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	for _, r := range d {
		if !(r == '.' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 127) {
			return false
		}
	}
	return !strings.HasPrefix(d, ".") && !strings.HasSuffix(d, ".") && !strings.Contains(d, "..")
}

// ---------- внешние списки ----------

func remotePath(c *Config, u string) string {
	h := sha1.Sum([]byte(u))
	return c.path(filepath.Join("remote", hex.EncodeToString(h[:])[:12]+".txt"))
}

// parseRemote разбирает скачанный список: неподходящие строки молча пропускаются
// (во внешних списках бывают заголовки и форматы для других программ).
func parseRemote(text string) (r Rules, skipped int) {
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimSpace(raw)
		// формат dnsmasq: server=/example.com/… или ipset=/example.com/…
		if i := strings.Index(raw, "=/"); i > 0 && !strings.HasPrefix(raw, "=") {
			if parts := strings.Split(raw[i+2:], "/"); len(parts) > 0 {
				raw = parts[0]
			}
		}
		kind, v, err := parseLine(raw)
		switch {
		case err != nil || kind == "remote":
			skipped++
		case kind == "domain":
			r.Domains = append(r.Domains, v)
		case kind == "ip":
			r.IPs = append(r.IPs, v)
		}
	}
	return
}

// fetchRemote скачивает внешний список в кэш. Пишет на диск только при изменении.
func fetchRemote(ctx context.Context, c *Config, u string) error {
	b, _, err := fetchURL(ctx, c, u, "", 32<<20)
	if err != nil {
		return err
	}
	if r, _ := parseRemote(string(b)); r.empty() {
		return fmt.Errorf("в списке не нашлось ни одного домена или подсети")
	}
	_ = os.MkdirAll(c.path("remote"), 0o700)
	writeIfChanged(remotePath(c, u), b)
	return nil
}

// ---------- группы ----------

// Group — свои списки через свою часть узлов (например, «YouTube через Нидерланды»).
type Group struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Filter string `json:"filter"` // регулярное выражение по имени узла
}

const (
	groupsFile   = "groups.json"
	routeDefFile = "routing.json"
	maxGroups    = 8
)

// ---------- маршрут по умолчанию ----------

// routingState — настройка из routeDefFile: куда идёт трафик, который не
// попал ни в один список и группу. "direct" или "vpn"; пусто — авто
// (серверный режим: через VPN, роутер: напрямую).
type routingState struct {
	Default string `json:"default"`
}

// loadRouteDefault читает routing.json. Файла и мелких повреждений не боимся:
// отсутствие настройки — валидное состояние «авто».
func loadRouteDefault(c *Config) string {
	b, err := os.ReadFile(c.path(routeDefFile))
	if err != nil {
		return ""
	}
	var r routingState
	if json.Unmarshal(stripJSONComments(b), &r) != nil {
		return ""
	}
	if r.Default == "direct" || r.Default == "vpn" {
		return r.Default
	}
	return ""
}

// routeDefaultResolved — значение для страницы и генератора конфига: явный
// выбор, а при его отсутствии — дефолт режима.
func routeDefaultResolved(v string) string {
	if v == "direct" || v == "vpn" {
		return v
	}
	if serverMode {
		return "vpn"
	}
	return "direct"
}

var groupIDRe = regexp.MustCompile(`^g[0-9]{1,3}$`)

func groupListName(id string) string { return "group-" + id + ".txt" }

func loadGroups(c *Config) ([]Group, error) {
	var gs []Group
	usedBackup, err := readStateFile(c.path(groupsFile), &gs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if usedBackup {
		lg.Printf("%s повреждён — поднята .bak-копия", groupsFile)
	}
	return gs, validateGroups(gs)
}

func validateGroups(gs []Group) error {
	if len(gs) > maxGroups {
		return fmt.Errorf("групп не больше %d", maxGroups)
	}
	seen := map[string]bool{}
	for _, g := range gs {
		if !groupIDRe.MatchString(g.ID) || seen[g.ID] {
			return fmt.Errorf("неверный id группы %q", g.ID)
		}
		seen[g.ID] = true
		if strings.TrimSpace(g.Name) == "" {
			return fmt.Errorf("у группы %s нет названия", g.ID)
		}
		if _, err := regexp.Compile(g.Filter); err != nil {
			return fmt.Errorf("группа «%s»: ошибка в фильтре: %v", g.Name, err)
		}
	}
	return nil
}

// ---------- всё вместе ----------

type GroupRules struct {
	Group
	Rules
}

// RouteSet — всё, из чего собирается 05_routing.json.
type RouteSet struct {
	Direct   Rules
	VPN      Rules
	Groups   []GroupRules
	Remotes  []string // все ссылки на внешние списки
	Warnings []string // внешние списки, которых ещё нет в кэше, и т. п.
	Default  string   // "" | "direct" | "vpn" — куда трафик вне списков
}

// readRouting читает direct.txt, vpn.txt, группы и подставляет сохранённые внешние списки.
func readRouting(c *Config) (RouteSet, []string, error) {
	var rs RouteSet
	var errs []string
	rs.Default = loadRouteDefault(c)
	load := func(file string) (Rules, error) {
		b, err := os.ReadFile(c.path(file))
		if err != nil && !os.IsNotExist(err) {
			return Rules{}, err
		}
		r, remotes, e := parseListFull(string(b))
		for _, x := range e {
			errs = append(errs, file+": "+x)
		}
		for _, u := range remotes {
			rs.Remotes = append(rs.Remotes, u)
			cached, err := os.ReadFile(remotePath(c, u))
			if err != nil {
				rs.Warnings = append(rs.Warnings, fmt.Sprintf("%s: внешний список %s ещё не скачан", file, u))
				continue
			}
			rr, _ := parseRemote(string(cached))
			r.add(rr)
		}
		return r, nil
	}
	var err error
	if rs.Direct, err = load("direct.txt"); err != nil {
		return rs, nil, err
	}
	if rs.VPN, err = load("vpn.txt"); err != nil {
		return rs, nil, err
	}
	groups, err := loadGroups(c)
	if err != nil {
		return rs, nil, err
	}
	for _, g := range groups {
		r, err := load(groupListName(g.ID))
		if err != nil {
			return rs, nil, err
		}
		rs.Groups = append(rs.Groups, GroupRules{Group: g, Rules: r})
	}
	return rs, errs, nil
}

// TargetDef — куда направляется «VPN»-трафик: основной балансировщик или балансировщик группы.
type TargetDef struct {
	ID        string   // "" — основной
	Name      string   // для журнала и страницы
	Balancer  string   // тег балансировщика
	ProbePort int      // локальный вход для проверки «как ходит трафик этой цели»
	Tags      []string // узлы цели; nil — все узлы
	Empty     bool     // в группе нет подходящих узлов — её трафик идёт основной целью
}

// targetDefs вычисляет цели: основная + группы с узлами по фильтру.
func targetDefs(c *Config, nodes []Node, groups []Group) []TargetDef {
	defs := []TargetDef{{Name: "основной", Balancer: c.Xray.Balancer, ProbePort: c.Xray.ProbePort}}
	for i, g := range groups {
		d := TargetDef{ID: g.ID, Name: g.Name, Balancer: c.Xray.Balancer + "-" + g.ID, ProbePort: c.Xray.ProbePort + 1 + i}
		re, err := regexp.Compile(g.Filter)
		if err == nil {
			for _, n := range nodes {
				if re.MatchString(n.Name) {
					d.Tags = append(d.Tags, n.Tag)
				}
			}
		}
		d.Empty = len(d.Tags) == 0
		defs = append(defs, d)
	}
	return defs
}
