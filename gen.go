package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	routingFile = "05_routing.json"
	xsubFile    = "07_xsub.json"
	probeTag    = "xsub-probe"
	testPrefix  = "xsub-test-"
	ownDirect   = "xsub-direct"
)

func testTag(n Node) string {
	if isFallbackTag(n.Tag) {
		return testPrefix + n.Tag
	}
	return testPrefix + strings.TrimPrefix(n.Tag, "node-")
}

// Env — то, что уже есть в конфигах Xray помимо файлов xsub.
type Env struct {
	OutTags      map[string]string         // tag -> protocol
	RawOut       map[string]map[string]any // tag -> outbound целиком (для переноса в резервы xsub)
	FirstFreedom string
	InTags       map[string]bool
	Sniff        map[string]bool // входы с включённым sniffing (нужен для правил по доменам)
	sockByTag    map[string]any
	anySockopt   any
	API          []string // файлы с секцией api
	Observatory  []string // файлы с observatory / burstObservatory
	LaterRouting []string // файлы с routing, читаемые после 05_routing.json
}

// scanEnv читает все *.json из папки конфигов (кроме файлов xsub).
func scanEnv(c *Config) (Env, error) {
	e := Env{OutTags: map[string]string{}, RawOut: map[string]map[string]any{}, InTags: map[string]bool{}, sockByTag: map[string]any{}}
	files, _ := filepath.Glob(filepath.Join(c.Xray.ConfDir, "*.json"))
	sort.Strings(files)
	for _, f := range files {
		base := filepath.Base(f)
		if base == routingFile || base == xsubFile {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return e, err
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(stripJSONComments(b), &doc); err != nil {
			return e, fmt.Errorf("%s: %v", base, err)
		}
		if _, ok := doc["api"]; ok {
			e.API = append(e.API, base)
		}
		if _, ok := doc["observatory"]; ok {
			e.Observatory = append(e.Observatory, base)
		}
		if _, ok := doc["burstObservatory"]; ok {
			e.Observatory = append(e.Observatory, base)
		}
		if _, ok := doc["routing"]; ok && base > routingFile {
			e.LaterRouting = append(e.LaterRouting, base)
		}
		var outs []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Stream   struct {
				Sockopt any `json:"sockopt"`
			} `json:"streamSettings"`
		}
		if raw, ok := doc["outbounds"]; ok {
			_ = json.Unmarshal(raw, &outs)
			var full []map[string]any
			_ = json.Unmarshal(raw, &full)
			for _, o := range full {
				if t := anyStr(o["tag"]); t != "" {
					e.RawOut[t] = o
				}
			}
		}
		for _, o := range outs {
			if o.Tag == "" {
				continue
			}
			e.OutTags[o.Tag] = o.Protocol
			if o.Protocol == "freedom" && e.FirstFreedom == "" {
				e.FirstFreedom = o.Tag
			}
			if o.Stream.Sockopt != nil {
				e.sockByTag[o.Tag] = o.Stream.Sockopt
				if e.anySockopt == nil && o.Protocol != "blackhole" {
					e.anySockopt = o.Stream.Sockopt
				}
			}
		}
		var ins []struct {
			Tag      string `json:"tag"`
			Sniffing struct {
				Enabled bool `json:"enabled"`
			} `json:"sniffing"`
		}
		if raw, ok := doc["inbounds"]; ok {
			_ = json.Unmarshal(raw, &ins)
		}
		for _, in := range ins {
			if in.Tag != "" {
				e.InTags[in.Tag] = true
				if in.Sniffing.Enabled {
					if e.Sniff == nil {
						e.Sniff = map[string]bool{}
					}
					e.Sniff[in.Tag] = true
				}
			}
		}
	}
	return e, nil
}

// Sockopt для узлов подписки: у template_tag, иначе у первого outbound, где он задан
// (XKeen помечает исходящий трафик ядра, чтобы он не заворачивался обратно).
func (e Env) Sockopt(c *Config) any {
	if c.Xray.TemplateTag != "" {
		if s, ok := e.sockByTag[c.Xray.TemplateTag]; ok {
			return s
		}
	}
	return e.anySockopt
}

func (e Env) directTag(c *Config) (tag string, own bool) {
	if p, ok := e.OutTags[c.Xray.DirectTag]; ok && p == "freedom" {
		return c.Xray.DirectTag, false
	}
	if e.FirstFreedom != "" {
		return e.FirstFreedom, false
	}
	return ownDirect, true
}

func (e Env) fallbackTag(c *Config) string {
	if c.Xray.FallbackTag == "" {
		return ""
	}
	if _, ok := e.OutTags[c.Xray.FallbackTag]; ok {
		return c.Xray.FallbackTag
	}
	return ""
}

// check — конфликты, при которых xsub не может безопасно управлять Xray.
func (e Env) check(c *Config) error {
	var errs []string
	if c.Xray.ManageAPI && len(e.API) > 0 {
		errs = append(errs, fmt.Sprintf("в %s уже есть секция api — xsub добавляет свою. Удалите её или задайте в config.json \"manage_api\": false и включите RoutingService на адресе %s",
			strings.Join(e.API, ", "), c.Xray.APIListen))
	}
	if len(e.Observatory) > 0 {
		errs = append(errs, fmt.Sprintf("в %s уже есть observatory — xsub нужен свой; удалите его оттуда", strings.Join(e.Observatory, ", ")))
	}
	if len(e.LaterRouting) > 0 {
		errs = append(errs, fmt.Sprintf("в %s есть секция routing, и она перекроет %s — перенесите правила в списки xsub", strings.Join(e.LaterRouting, ", "), routingFile))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return nil
}

// generate собирает содержимое 05_routing.json и 07_xsub.json.
// fbs — резервные узлы xsub (в порядке приоритета); первый из них — fallbackTag балансировщиков.
func generate(c *Config, env Env, nodes, fbs []Node, rs RouteSet) (routing, xsub []byte, err error) {
	if err := env.check(c); err != nil {
		return nil, nil, err
	}
	x := c.Xray
	directTag, ownDir := env.directTag(c)
	fallback := env.fallbackTag(c) // старый способ: outbound из конфигов XKeen (xray.fallback_tag)
	if len(fbs) > 0 {
		fallback = fbs[0].Tag
	}
	var groups []Group
	for _, g := range rs.Groups {
		groups = append(groups, g.Group)
	}
	defs := targetDefs(c, nodes, groups)

	rule := func(match map[string]any, t map[string]any) map[string]any {
		r := map[string]any{"type": "field"}
		for k, v := range match {
			r[k] = v
		}
		for k, v := range t {
			r[k] = v
		}
		return r
	}
	direct := map[string]any{"outboundTag": directTag}
	// Цель основного «VPN»-трафика: балансировщик по узлам подписок или запасной outbound.
	var mainTarget map[string]any
	switch {
	case len(nodes) > 0:
		mainTarget = map[string]any{"balancerTag": x.Balancer}
	case fallback != "":
		mainTarget = map[string]any{"outboundTag": fallback}
	}
	targetOf := func(d TargetDef) map[string]any {
		if d.ID == "" || d.Empty {
			return mainTarget
		}
		return map[string]any{"balancerTag": d.Balancer}
	}

	var rules, inbounds []any
	for _, d := range defs {
		if d.ID != "" && d.Empty {
			continue // у группы нет узлов — проверять нечего, её трафик идёт основной целью
		}
		if t := targetOf(d); t != nil {
			tag := probeTag
			if d.ID != "" {
				tag += "-" + d.ID
			}
			rules = append(rules, rule(map[string]any{"inboundTag": []string{tag}}, t))
			inbounds = append(inbounds, socksIn(tag, d.ProbePort))
		}
	}
	for _, n := range append(append([]Node(nil), nodes...), fbs...) {
		rules = append(rules, rule(map[string]any{"inboundTag": []string{testTag(n)}}, map[string]any{"outboundTag": n.Tag}))
	}
	var force []string
	for _, t := range x.ForceProxyInbounds {
		if env.InTags[t] {
			force = append(force, t)
		}
	}
	if mainTarget != nil && len(force) > 0 {
		rules = append(rules, rule(map[string]any{"inboundTag": force}, mainTarget))
	}
	addRules := func(r Rules, t map[string]any) {
		if t == nil {
			return
		}
		if len(r.Domains) > 0 {
			rules = append(rules, rule(map[string]any{"domain": r.Domains}, t))
		}
		if len(r.IPs) > 0 {
			rules = append(rules, rule(map[string]any{"ip": r.IPs}, t))
		}
	}
	addRules(rs.Direct, direct)
	for i, g := range rs.Groups {
		addRules(g.Rules, targetOf(defs[i+1]))
	}
	addRules(rs.VPN, mainTarget)
	// Трафик вне списков и групп — по переключателю «По умолчанию».
	rules = append(rules, rule(map[string]any{"network": "tcp,udp"}, defaultTarget(rs.Default, mainTarget, direct)))

	rt := map[string]any{"domainStrategy": "AsIs", "rules": rules}
	if len(nodes) > 0 {
		var bals []any
		for _, d := range defs {
			if d.Empty && d.ID != "" {
				continue
			}
			sel := []string{"node-"}
			if d.ID != "" {
				sel = d.Tags
			}
			bal := map[string]any{"tag": d.Balancer, "selector": sel, "strategy": map[string]any{"type": "leastPing"}}
			if fallback != "" {
				bal["fallbackTag"] = fallback
			}
			bals = append(bals, bal)
		}
		rt["balancers"] = bals
	}
	routing, err = marshal(map[string]any{"routing": rt})
	if err != nil {
		return
	}

	var outbounds []any
	for i, n := range append(append([]Node(nil), nodes...), fbs...) {
		inbounds = append(inbounds, socksIn(testTag(n), x.TestPortBase+i))
		outbounds = append(outbounds, n.Outbound)
	}
	if ownDir {
		ob := map[string]any{"tag": ownDirect, "protocol": "freedom"}
		if so := env.Sockopt(c); so != nil {
			ob["streamSettings"] = map[string]any{"sockopt": so}
		}
		outbounds = append(outbounds, ob)
	}
	doc := map[string]any{}
	if x.ManageAPI {
		doc["api"] = map[string]any{"tag": "xsub-api", "listen": x.APIListen, "services": []string{"RoutingService"}}
	}
	if len(inbounds) > 0 {
		doc["inbounds"] = inbounds
	}
	if len(outbounds) > 0 {
		doc["outbounds"] = outbounds
	}
	if len(nodes) > 0 {
		doc["observatory"] = map[string]any{
			"subjectSelector":   []string{"node-"},
			"probeURL":          x.ObservatoryURL,
			"probeInterval":     x.ObservatoryEvery,
			"enableConcurrency": true,
		}
	}
	xsub, err = marshal(doc)
	return
}

func socksIn(tag string, port int) map[string]any {
	return map[string]any{
		"tag":      tag,
		"listen":   "127.0.0.1",
		"port":     port,
		"protocol": "socks",
		"settings": map[string]any{"auth": "noauth", "udp": false},
	}
}

// defaultTarget — куда идёт трафик, который не попал ни в один список и группу:
// через балансировщик или напрямую. «Через VPN» без единого узла оборачивается
// напрямую — проксировать не через кого.
func defaultTarget(routeDefault string, mainTarget, direct map[string]any) map[string]any {
	if routeDefaultResolved(routeDefault) == "vpn" && mainTarget != nil {
		return mainTarget
	}
	return direct
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
