package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Node — один узел подписки, уже переведённый в outbound Xray.
type Node struct {
	Tag      string         `json:"tag"`
	Name     string         `json:"name"`
	Sub      string         `json:"sub"`
	Proto    string         `json:"proto"`
	Address  string         `json:"address"`
	Port     int            `json:"port"`
	Warn     string         `json:"warn,omitempty"`
	Outbound map[string]any `json:"-"`
}

// fetchURL качает ссылку: сначала напрямую, при неудаче — через VPN (локальный probe-вход Xray).
// Переданный контекст рвёт загрузку, когда ушёл пользователь или остановился xsub.
func fetchURL(ctx context.Context, c *Config, u, ua string, limit int64) ([]byte, http.Header, error) {
	h := http.Header{}
	if ua != "" {
		h.Set("User-Agent", ua)
	}
	return fetchURLHeaders(ctx, c, u, h, limit)
}

// fetchURLHeaders — то же, что fetchURL, но с произвольными заголовками запроса.
func fetchURLHeaders(ctx context.Context, c *Config, u string, hdr http.Header, limit int64) ([]byte, http.Header, error) {
	try := func(proxyPort int) ([]byte, http.Header, error) {
		tr := &http.Transport{DisableKeepAlives: true}
		if proxyPort > 0 {
			tr.Proxy = http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", proxyPort)})
		}
		cl := &http.Client{Transport: tr, Timeout: 90 * time.Second}
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		resp, err := cl.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		return b, resp.Header, err
	}
	b, h, err := try(0)
	if err == nil {
		return b, h, nil
	}
	b, h, err2 := try(c.Xray.ProbePort)
	if err2 == nil {
		return b, h, nil
	}
	return nil, nil, fmt.Errorf("напрямую: %v; через VPN: %v", cleanErr(err), cleanErr(err2))
}

// subHeaders — заголовки запроса подписки. hwid отправляется, как это делают
// Happ, v2RayTun и др.: панели с лимитом устройств (Remnawave и др.) без него
// отдают вместо узлов заглушки на 0.0.0.0. Пустой hwid — без него.
func subHeaders(ua, hwid string) http.Header {
	h := http.Header{}
	if ua != "" {
		h.Set("User-Agent", ua)
	}
	if hwid != "" {
		h.Set("X-Hwid", hwid)
		h.Set("X-Device-Os", "Linux")
		h.Set("X-Device-Model", "xsub router")
	}
	return h
}

var (
	hwidMu    sync.Mutex
	hwidCache string
)

// deviceHWID — постоянный идентификатор роутера для панели подписок. Хранится в
// файле hwid рядом с конфигом (и в памяти — на случай, если файл не записать):
// при каждом новом значении панель считала бы роутер новым устройством.
// В файл можно вписать HWID своего устройства.
func deviceHWID(c *Config) string {
	hwidMu.Lock()
	defer hwidMu.Unlock()
	if hwidCache != "" {
		return hwidCache
	}
	p := c.path("hwid")
	if b, err := os.ReadFile(p); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			hwidCache = id
			return id
		}
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	hwidCache = hex.EncodeToString(buf)
	if err := os.WriteFile(p, []byte(hwidCache+"\n"), 0o600); err != nil {
		lg.Printf("не удалось сохранить HWID: %v", err)
	}
	return hwidCache
}

// cleanErr убирает из ошибки адрес подписки (в нём часто секретный токен).
func cleanErr(err error) string {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err.Error()
	}
	return err.Error()
}

// UserInfo — заголовок subscription-userinfo: трафик и срок действия.
type UserInfo struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

func parseUserInfo(h http.Header) *UserInfo {
	v := h.Get("Subscription-Userinfo")
	if v == "" {
		return nil
	}
	ui := &UserInfo{}
	for _, part := range strings.Split(v, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		switch strings.ToLower(kv[0]) {
		case "upload":
			ui.Upload = n
		case "download":
			ui.Download = n
		case "total":
			ui.Total = n
		case "expire":
			ui.Expire = n
		}
	}
	return ui
}

// decodeSubscription: base64 (любой вариант) или сразу текст.
func decodeSubscription(b []byte) string {
	s := strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	if strings.Contains(s, "://") || strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") || looksClash(s) {
		return s
	}
	if d, ok := decodeB64(s); ok {
		return strings.TrimSpace(d)
	}
	return s
}

// decodeB64 разбирает любой вариант base64. Кодировка выбирается по самой строке,
// а не перебором: DecodeString сразу выделяет буфер под весь результат, и на теле
// подписки в несколько мегабайт четыре попытки подряд — это десятки мегабайт
// впустую на роутере, где всей памяти сотня-другая.
func decodeB64(s string) (string, bool) {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if clean == "" {
		return "", false
	}
	// Алфавит и наличие дополнения видны по самой строке, перебирать не нужно.
	enc := base64.StdEncoding
	if strings.ContainsAny(clean, "-_") {
		enc = base64.URLEncoding
	}
	if !strings.HasSuffix(clean, "=") && len(clean)%4 != 0 {
		enc = enc.WithPadding(base64.NoPadding)
	}
	if d, err := enc.DecodeString(clean); err == nil {
		return string(d), true
	}
	return "", false
}

type parseOpts struct {
	sub      string
	exclude  *regexp.Regexp
	include  *regexp.Regexp
	sockopt  any
	maxNodes int
}

// entry — узел подписки до фильтрации: либо ссылка, либо готовый outbound (JSON Xray).
type entry struct {
	link string
	node *Node
	err  error
	name string
}

// parseSubscription разбирает тело подписки любого поддерживаемого формата.
func parseSubscription(body string, o parseOpts) ([]Node, []string) {
	text := decodeSubscription([]byte(body))
	entries, format, warns := expand(text, o.sockopt)
	var nodes []Node
	seen := map[string]bool{}
	skippedInfo := 0
	for _, e := range entries {
		var n Node
		err := e.err
		if err == nil && e.node != nil {
			n = *e.node
		} else if err == nil {
			n, err = parseLink(e.link, o.sockopt)
		}
		if err == errInfoNode {
			skippedInfo++
			continue
		}
		if err != nil {
			what := e.name
			if what == "" {
				what = short(e.link)
			}
			warns = append(warns, fmt.Sprintf("пропущен узел %s: %v", what, err))
			continue
		}
		if o.exclude != nil && o.exclude.MatchString(n.Name) {
			continue
		}
		if o.include != nil && !o.include.MatchString(n.Name) {
			continue
		}
		if seen[n.Tag] {
			continue
		}
		seen[n.Tag] = true
		n.Sub = o.sub
		if n.Warn != "" {
			warns = append(warns, fmt.Sprintf("%s: %s", n.Name, n.Warn))
		}
		nodes = append(nodes, n)
		if o.maxNodes > 0 && len(nodes) >= o.maxNodes {
			warns = append(warns, fmt.Sprintf("взяты первые %d узлов", o.maxNodes))
			break
		}
	}
	if skippedInfo > 0 {
		warns = append(warns, fmt.Sprintf("пропущено информационных записей (не серверов): %d", skippedInfo))
	}
	if format != "" && len(nodes) > 0 {
		warns = append([]string{"формат подписки: " + format}, warns...)
	}
	return nodes, warns
}

// expand превращает текст подписки в список узлов.
func expand(text string, sockopt any) ([]entry, string, []string) {
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		if es, format, err := fromJSON(text, sockopt); err == nil {
			return es, format, nil
		} else if !strings.Contains(text, "://") {
			return nil, "", []string{"не удалось разобрать JSON: " + err.Error()}
		}
	}
	if looksClash(text) {
		es, err := fromClash(text)
		if err != nil {
			return nil, "", []string{"не удалось разобрать Clash YAML: " + err.Error()}
		}
		return es, "Clash/mihomo YAML", nil
	}
	var es []entry
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		es = append(es, entry{link: line})
	}
	return es, "", nil
}

var errInfoNode = fmt.Errorf("информационная запись")

func short(s string) string {
	if i := strings.Index(s, "://"); i > 0 {
		if j := strings.LastIndex(s, "@"); j > i {
			s = s[:i+3] + "…" + s[j:]
		} else if len(s) > i+3+8 {
			s = s[:i+3+8] + "…"
		}
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

func isInfoAddress(host string, port int) bool {
	if port <= 1 || port > 65535 || host == "" || host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsUnspecified() || ip.IsLoopback()
	}
	return false
}

// identityTag — тег узла по стабильным полям: протокол, адрес, порт, тип транспорта,
// режим безопасности и учётная запись (UUID или пароль).
// SNI и path намеренно не включены: панели (Remnawave, gsupport и другие) ротируют их
// между запросами для обхода DPI, что делало все узлы «новыми» после каждого обновления.
// ShortId Reality не входил в хеш изначально — по той же причине.
func identityTag(prefix string, ob map[string]any) string {
	host, port := outboundAddr(ob)
	ss, _ := ob["streamSettings"].(map[string]any)
	parts := []string{anyStr(ob["protocol"]), strings.ToLower(host), strconv.Itoa(port), nodeCredential(ob)}
	if ss != nil {
		parts = append(parts, anyStr(ss["network"]), anyStr(ss["security"]))
	}
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return prefix + hex.EncodeToString(h[:])[:8]
}

// nodeCredential извлекает UUID или пароль из outbound для использования в identityTag.
func nodeCredential(ob map[string]any) string {
	st, _ := ob["settings"].(map[string]any)
	if st == nil {
		return ""
	}
	if l, _ := st["vnext"].([]any); len(l) > 0 { // vless, vmess
		if m, _ := l[0].(map[string]any); m != nil {
			if users, _ := m["users"].([]any); len(users) > 0 {
				if u, _ := users[0].(map[string]any); u != nil {
					return anyStr(u["id"])
				}
			}
		}
	}
	if l, _ := st["servers"].([]any); len(l) > 0 { // trojan, shadowsocks, hysteria2
		if m, _ := l[0].(map[string]any); m != nil {
			return anyStr(m["password"])
		}
	}
	return ""
}

func hostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if isInfoAddress(host, port) {
		return "", 0, errInfoNode
	}
	return host, port, nil
}

func nameOf(u *url.URL, host string) string {
	if u.Fragment != "" {
		return strings.TrimSpace(u.Fragment)
	}
	return host
}

// tlsSettings — общие параметры TLS из ссылки. Возвращает предупреждение, если что-то пришлось опустить.
func tlsSettings(q url.Values, sni, defALPN string) (map[string]any, string) {
	ts := map[string]any{}
	var warn string
	if sni != "" {
		ts["serverName"] = sni
	}
	if fp := q.Get("fp"); fp != "" {
		ts["fingerprint"] = strings.ToLower(fp)
	}
	alpn := q.Get("alpn")
	if alpn == "" {
		alpn = defALPN
	}
	if alpn != "" {
		ts["alpn"] = strings.Split(alpn, ",")
	}
	pin := firstNonEmpty(q.Get("pcs"), q.Get("pinSHA256"), q.Get("pinsha256"))
	if pin != "" {
		ts["pinnedPeerCertSha256"] = pin
	}
	if v := q.Get("vcn"); v != "" {
		ts["verifyPeerCertByName"] = v
	}
	if v := q.Get("ech"); v != "" {
		ts["echConfigList"] = v
	}
	ins := strings.ToLower(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure")))
	if (ins == "1" || ins == "true") && pin == "" {
		warn = "ссылка просит не проверять сертификат (insecure), а Xray так больше не умеет — узел заработает, только если сертификат настоящий"
	}
	return ts, warn
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// buildStream собирает streamSettings из параметров ссылки (общий формат vless/trojan/vmess).
func buildStream(q url.Values, defSecurity string, sockopt any) (map[string]any, string, error) {
	network := strings.ToLower(q.Get("type"))
	switch network {
	case "", "tcp", "raw":
		network = "tcp"
	case "splithttp":
		network = "xhttp"
	case "mkcp":
		network = "kcp"
	case "websocket":
		network = "ws"
	case "ws", "grpc", "xhttp", "httpupgrade", "kcp":
	case "h2", "http", "quic":
		return nil, "", fmt.Errorf("транспорт %s удалён из Xray", network)
	default:
		return nil, "", fmt.Errorf("транспорт %q не поддерживается", network)
	}

	security := strings.ToLower(q.Get("security"))
	if security == "" {
		security = defSecurity
	}
	stream := map[string]any{"network": network, "security": security}
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"))
	var warn string
	switch security {
	case "reality":
		if q.Get("pbk") == "" {
			return nil, "", fmt.Errorf("reality без pbk")
		}
		fp := q.Get("fp")
		if fp == "" {
			fp = "chrome"
		}
		rs := map[string]any{"serverName": sni, "fingerprint": strings.ToLower(fp), "publicKey": q.Get("pbk"), "shortId": q.Get("sid")}
		if v := q.Get("spx"); v != "" {
			rs["spiderX"] = v
		}
		if v := q.Get("pqv"); v != "" {
			rs["mldsa65Verify"] = v
		}
		stream["realitySettings"] = rs
	case "tls":
		ts, w := tlsSettings(q, sni, "")
		warn = w
		stream["tlsSettings"] = ts
	case "none", "":
		stream["security"] = "none"
	default:
		return nil, "", fmt.Errorf("security %q не поддерживается", security)
	}

	hostHdr, path := q.Get("host"), q.Get("path")
	switch network {
	case "tcp":
		switch ht := q.Get("headerType"); ht {
		case "", "none":
		case "http":
			req := map[string]any{}
			if path != "" {
				req["path"] = strings.Split(path, ",")
			}
			if hostHdr != "" {
				req["headers"] = map[string]any{"Host": strings.Split(hostHdr, ",")}
			}
			stream["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		default:
			return nil, "", fmt.Errorf("tcp headerType=%s не поддерживается", ht)
		}
	case "ws", "httpupgrade":
		s := map[string]any{}
		if path != "" {
			s["path"] = path
		}
		if hostHdr != "" {
			s["host"] = hostHdr
		}
		stream[network+"Settings"] = s
	case "grpc":
		sn := firstNonEmpty(q.Get("serviceName"), path)
		s := map[string]any{"serviceName": sn}
		if q.Get("mode") == "multi" {
			s["multiMode"] = true
		}
		if v := q.Get("authority"); v != "" {
			s["authority"] = v
		}
		stream["grpcSettings"] = s
	case "xhttp":
		s := map[string]any{}
		if path != "" {
			s["path"] = path
		}
		if hostHdr != "" {
			s["host"] = hostHdr
		}
		if v := q.Get("mode"); v != "" {
			s["mode"] = v
		}
		if v := q.Get("extra"); v != "" {
			var extra any
			if jsonUnmarshal([]byte(v), &extra) == nil {
				s["extra"] = extra
			}
		}
		stream["xhttpSettings"] = s
	case "kcp":
		// Обфускация mKCP в современном Xray задаётся через finalmask.
		mk := map[string]any{}
		if seed := q.Get("seed"); seed != "" {
			mk["value"] = seed
		} else if ht := q.Get("headerType"); ht != "" && ht != "none" {
			ht = strings.TrimSuffix(strings.ToLower(ht), "-video") // wechat-video → wechat
			mk["header"] = ht
			if ht == "dns" && hostHdr != "" {
				mk["value"] = hostHdr
			}
		}
		stream["kcpSettings"] = map[string]any{}
		stream["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "mkcp-legacy", "settings": mk}}}
	}
	if sockopt != nil {
		stream["sockopt"] = sockopt
	}
	return stream, warn, nil
}
