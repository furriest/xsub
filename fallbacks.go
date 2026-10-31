package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Fallback — резервный узел, которым управляет xsub. Включается, когда не работает
// ни один узел подписок. Задаётся ссылкой (как в подписке) или готовым outbound Xray
// (так переносятся резервы из конфигов XKeen).
type Fallback struct {
	Name string `json:"name"`
	Link string `json:"link,omitempty"`
	// Interface — интерфейс самого роутера (nwg0, ovpn_br0…). Трафик уходит через
	// туннель, поднятый Keenetic OS, а не через Xray: WireGuard с обфускацией и часть
	// других протоколов роутер тянет лучше, чем ядро.
	Interface string         `json:"interface,omitempty"`
	Outbound  map[string]any `json:"outbound,omitempty"`
	// Import — тег outbound из конфигов Xray, который нужно перенести сюда (только при сохранении со страницы).
	Import string `json:"import,omitempty"`
}

const (
	fallbacksFile = "fallbacks.json"
	maxFallbacks  = 10
	fbPrefix      = "fb-"
)

func isFallbackTag(tag string) bool { return strings.HasPrefix(tag, fbPrefix) }

// ifaceProto — что показывается в столбце протокола у резерва через интерфейс.
const ifaceProto = "interface"

// IFNAMSIZ в ядре — 16 байт вместе с нулём.
var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,15}$`)

// interfaceNode собирает резерв через интерфейс роутера: outbound freedom, привязанный
// к интерфейсу через sockopt.interface (SO_BINDTODEVICE).
func interfaceNode(iface string, sockopt any) Node {
	so := map[string]any{}
	// Метка XKeen из шаблона: без неё исходящий трафик ядра завернётся обратно в Xray.
	if tmpl, ok := sockopt.(map[string]any); ok {
		for k, v := range tmpl {
			so[k] = v
		}
	}
	so["interface"] = iface
	h := sha1.Sum([]byte("iface|" + iface))
	tag := fbPrefix + hex.EncodeToString(h[:])[:8]
	return Node{
		Tag: tag, Name: iface, Proto: ifaceProto, Address: iface,
		Outbound: map[string]any{
			"tag":            tag,
			"protocol":       "freedom",
			"streamSettings": map[string]any{"sockopt": so},
		},
	}
}

// ifaceOf — к какому интерфейсу привязан готовый outbound (пусто, если ни к какому).
func ifaceOf(ob map[string]any) string {
	ss, _ := ob["streamSettings"].(map[string]any)
	so, _ := ss["sockopt"].(map[string]any)
	return anyStr(so["interface"])
}

// IfaceInfo — интерфейс роутера для выпадающего списка на странице.
type IfaceInfo struct {
	Name string `json:"name"`
	Addr string `json:"addr,omitempty"`
	Up   bool   `json:"up"`
}

// routerInterfaces — сетевые интерфейсы роутера, кроме петлевого.
func routerInterfaces() []IfaceInfo {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []IfaceInfo
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		info := IfaceInfo{Name: i.Name, Up: i.Flags&net.FlagUp != 0}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					info.Addr = ipn.IP.String()
					break
				}
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func loadFallbacks(c *Config) ([]Fallback, error) {
	var fbs []Fallback
	usedBackup, err := readStateFile(c.path(fallbacksFile), &fbs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if usedBackup {
		lg.Printf("%s повреждён — поднята .bak-копия", fallbacksFile)
	}
	return fbs, nil
}

func saveFallbacksFile(c *Config, fbs []Fallback) error {
	if fbs == nil {
		fbs = []Fallback{}
	}
	b, err := marshal(fbs)
	if err != nil {
		return err
	}
	return writeStateFile(c.path(fallbacksFile), b)
}

// fallbackNode переводит резерв в узел Xray с тегом fb-….
func fallbackNode(f Fallback, sockopt any) (Node, error) {
	var n Node
	var err error
	switch {
	case strings.TrimSpace(f.Interface) != "":
		iface := strings.TrimSpace(f.Interface)
		if !ifaceRe.MatchString(iface) {
			err = fmt.Errorf("%q не похоже на имя интерфейса", iface)
		} else {
			n = interfaceNode(iface, sockopt)
		}
	case strings.TrimSpace(f.Link) != "":
		n, err = parseLink(strings.TrimSpace(f.Link), sockopt)
		if err == errInfoNode {
			err = fmt.Errorf("в ссылке нет адреса сервера")
		}
		if err == nil {
			h := sha1.Sum([]byte(f.Link))
			n.Tag = fbPrefix + hex.EncodeToString(h[:])[:8]
			n.Outbound["tag"] = n.Tag
		}
	case f.Outbound != nil:
		n, err = outboundNode(copyMap(f.Outbound), f.Name, sockopt, fbPrefix)
		if err == errInfoNode {
			err = fmt.Errorf("в outbound нет адреса сервера")
		}
	default:
		err = fmt.Errorf("нужна ссылка или интерфейс")
	}
	if err != nil {
		return Node{}, err
	}
	if strings.TrimSpace(f.Name) != "" {
		n.Name = strings.TrimSpace(f.Name)
	}
	n.Sub = "резерв"
	return n, nil
}

// fallbackNodes — все резервы в порядке приоритета; неразобранные пропускаются с предупреждением.
func fallbackNodes(c *Config, sockopt any) ([]Node, []string) {
	fbs, err := loadFallbacks(c)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var nodes []Node
	var warns []string
	seen := map[string]bool{}
	for i, f := range fbs {
		n, err := fallbackNode(f, sockopt)
		if err != nil {
			warns = append(warns, fmt.Sprintf("резерв «%s»: %v", firstNonEmpty(f.Name, fmt.Sprint(i+1)), err))
			continue
		}
		if seen[n.Tag] {
			continue
		}
		seen[n.Tag] = true
		nodes = append(nodes, n)
	}
	return nodes, warns
}

// prepareFallbacks проверяет список со страницы и подставляет outbound'ы для переноса из конфигов Xray.
func prepareFallbacks(c *Config, fbs []Fallback) ([]Fallback, error) {
	if len(fbs) > maxFallbacks {
		return nil, fmt.Errorf("резервов не больше %d", maxFallbacks)
	}
	env, err := scanEnv(c)
	if err != nil {
		return nil, err
	}
	out := make([]Fallback, 0, len(fbs))
	for i, f := range fbs {
		f.Name = strings.TrimSpace(f.Name)
		f.Link = strings.TrimSpace(f.Link)
		if f.Import != "" {
			raw, ok := env.RawOut[f.Import]
			if !ok {
				return nil, fmt.Errorf("в конфигах Xray нет outbound %q", f.Import)
			}
			ob := copyMap(raw)
			delete(ob, "tag")
			f.Outbound, f.Link, f.Interface = ob, "", ""
			// freedom, привязанный к интерфейсу, переносим как резерв-интерфейс:
			// так его видно и можно поправить, а не прятать в сыром outbound.
			if anyStr(ob["protocol"]) == "freedom" {
				f.Interface, f.Outbound = ifaceOf(ob), nil
			}
			if f.Name == "" {
				f.Name = f.Import
			}
			f.Import = ""
		}
		f.Interface = strings.TrimSpace(f.Interface)
		if f.Interface != "" {
			f.Link, f.Outbound = "", nil
		}
		if f.Name == "" {
			f.Name = fmt.Sprintf("Резерв %d", i+1)
		}
		if _, err := fallbackNode(f, nil); err != nil {
			return nil, fmt.Errorf("резерв «%s»: %v", f.Name, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// sameOutbound — outbound'ы совпадают без учёта тега (чтобы показать «уже перенесён»).
func sameOutbound(a, b map[string]any) bool {
	strip := func(m map[string]any) string {
		cp := map[string]any{}
		for k, v := range m {
			if k != "tag" {
				cp[k] = v
			}
		}
		s, _ := json.Marshal(cp)
		return string(s)
	}
	return strip(a) == strip(b)
}

type FallbackView struct {
	Fallback
	Tag     string `json:"tag"`
	Summary string `json:"summary"`
	Err     string `json:"err,omitempty"`
	Warn    string `json:"warn,omitempty"`
}

type ImportCandidate struct {
	Tag      string `json:"tag"`
	Summary  string `json:"summary"`
	Imported bool   `json:"imported"`
	Legacy   bool   `json:"legacy"` // указан в xray.fallback_tag
}

func nodeSummary(n Node) string {
	switch {
	case n.Address == "":
		return n.Proto
	case n.Port == 0: // резерв через интерфейс роутера: порта нет
		return n.Proto + " " + n.Address
	}
	return fmt.Sprintf("%s %s:%d", n.Proto, n.Address, n.Port)
}

// uiFallbacks — резервы для страницы и outbound'ы из конфигов Xray, которые можно перенести.
func (a *App) uiFallbacks() map[string]any {
	fbs, err := loadFallbacks(a.c)
	ifaces := routerInterfaces()
	have := map[string]bool{}
	for _, i := range ifaces {
		have[i.Name] = true
	}
	views := []FallbackView{}
	for _, f := range fbs {
		v := FallbackView{Fallback: f}
		if n, err := fallbackNode(f, nil); err != nil {
			v.Err = err.Error()
		} else {
			v.Tag, v.Summary = n.Tag, nodeSummary(n)
		}
		// Опечатка в имени интерфейса иначе обнаружилась бы только при отказе всех узлов.
		if f.Interface != "" && v.Err == "" && !have[f.Interface] {
			v.Warn = "такого интерфейса сейчас нет на роутере"
		}
		views = append(views, v)
	}
	cands := []ImportCandidate{}
	env, _ := scanEnv(a.c)
	var tags []string
	for t := range env.RawOut {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	for _, t := range tags {
		ob := env.RawOut[t]
		if strings.HasPrefix(t, "node-") || isFallbackTag(t) || strings.HasPrefix(t, "xsub-") {
			continue
		}
		// freedom подходит в резерв, только если привязан к интерфейсу: без привязки
		// это обычное прямое соединение, и трафик пошёл бы мимо VPN незаметно для хозяина.
		proto := anyStr(ob["protocol"])
		if proto == "freedom" {
			if ifaceOf(ob) == "" {
				continue
			}
		} else if !xrayProxyProtocols[proto] {
			continue
		}
		ic := ImportCandidate{Tag: t, Legacy: t == a.c.Xray.FallbackTag && len(fbs) == 0}
		if proto == "freedom" {
			ic.Summary = nodeSummary(interfaceNode(ifaceOf(ob), nil))
		} else if n, err := outboundNode(copyMap(ob), t, nil, fbPrefix); err == nil {
			ic.Summary = nodeSummary(n)
		} else {
			ic.Summary = err.Error()
		}
		for _, f := range fbs {
			if f.Outbound != nil && sameOutbound(f.Outbound, ob) {
				ic.Imported = true
			}
			if proto == "freedom" && f.Interface != "" && f.Interface == ifaceOf(ob) {
				ic.Imported = true
			}
		}
		cands = append(cands, ic)
	}
	res := map[string]any{"fallbacks": views, "imports": cands, "interfaces": ifaces}
	if err != nil {
		res["error"] = err.Error()
	}
	return res
}

func copyMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// saveFallbacks сохраняет резервы и применяет конфиг; при ошибке возвращает прежний список.
func (a *App) saveFallbacks(in []Fallback) error {
	fbs, err := prepareFallbacks(a.c, in)
	if err != nil {
		return err
	}
	opMu.Lock()
	defer opMu.Unlock()
	old, _ := loadFallbacks(a.c)
	if err := saveFallbacksFile(a.c, fbs); err != nil {
		return err
	}
	a.mu.Lock()
	nodes := a.nodes
	a.mu.Unlock()
	if err := a.apply(nodes, "изменены резервные узлы", false); err != nil {
		_ = saveFallbacksFile(a.c, old)
		return err
	}
	lg.Printf("резервные узлы сохранены: %d", len(fbs))
	return nil
}
