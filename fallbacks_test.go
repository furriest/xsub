package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const testOutboundsConf = `{"outbounds":[{"tag":"vless-reality","protocol":"vless","settings":{"vnext":[{"address":"example.org","port":443,"users":[{"id":"` + tUUID + `","encryption":"none"}]}]},
	"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"a.example","fingerprint":"chrome","publicKey":"` + tPBK + `","shortId":"ab"},"sockopt":{"mark":255}}},
	{"tag":"backup-proxy","protocol":"socks","settings":{"servers":[{"address":"proxy.example.com","port":1080}]}},
	{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}`

func TestFallbackNode(t *testing.T) {
	n, err := fallbackNode(Fallback{Name: "Мой прокси", Link: "socks://user:pass@proxy.example.com:1080#x"}, map[string]any{"mark": 255})
	if err != nil {
		t.Fatal(err)
	}
	if !isFallbackTag(n.Tag) || n.Outbound["tag"] != n.Tag || n.Name != "Мой прокси" || n.Sub != "резерв" || n.Address != "proxy.example.com" {
		t.Fatalf("узел по ссылке: %+v", n)
	}
	ob := map[string]any{"protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "proxy.example.com", "port": 1080}}}}
	n2, err := fallbackNode(Fallback{Name: "imp", Outbound: ob}, nil)
	if err != nil || !isFallbackTag(n2.Tag) || n2.Port != 1080 {
		t.Fatalf("узел из outbound: %+v %v", n2, err)
	}
	if _, has := ob["tag"]; has {
		t.Error("исходный outbound не должен меняться")
	}
	if _, err := fallbackNode(Fallback{Name: "пусто"}, nil); err == nil {
		t.Error("резерв без ссылки должен давать ошибку")
	}
	if _, err := fallbackNode(Fallback{Link: "tuic://x@example.com:1"}, nil); err == nil {
		t.Error("неподдерживаемая ссылка должна давать ошибку")
	}
}

func TestPrepareFallbacksImport(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	writeConf(t, c.Xray.ConfDir, map[string]string{"04_outbounds.json": testOutboundsConf})
	fbs, err := prepareFallbacks(c, []Fallback{{Import: "vless-reality"}, {Link: " socks://proxy.example.com:1080 "}})
	if err != nil {
		t.Fatal(err)
	}
	if fbs[0].Name != "vless-reality" || fbs[0].Outbound == nil || fbs[0].Import != "" || fbs[0].Outbound["tag"] != nil {
		t.Fatalf("перенос: %+v", fbs[0])
	}
	if fbs[1].Link != "socks://proxy.example.com:1080" || fbs[1].Name != "Резерв 2" {
		t.Fatalf("ссылка: %+v", fbs[1])
	}
	if _, err := prepareFallbacks(c, []Fallback{{Import: "нет-такого"}}); err == nil {
		t.Error("перенос несуществующего outbound должен давать ошибку")
	}
	if _, err := prepareFallbacks(c, []Fallback{{Import: "direct"}}); err == nil {
		t.Error("freedom не годится в резерв")
	}
	if err := saveFallbacksFile(c, fbs); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(c.path(fallbacksFile)); st.Mode().Perm() != 0o600 {
		t.Errorf("права fallbacks.json: %v", st.Mode())
	}
	nodes, warns := fallbackNodes(c, nil)
	if len(nodes) != 2 || len(warns) != 0 {
		t.Fatalf("fallbackNodes: %d %v", len(nodes), warns)
	}
	a := &App{c: c}
	ui := a.uiFallbacks()
	imps := ui["imports"].([]ImportCandidate)
	if len(imps) != 2 || imps[1].Tag != "vless-reality" || !imps[1].Imported || imps[0].Imported || imps[1].Legacy {
		t.Fatalf("кандидаты на перенос: %+v", imps)
	}
}

func TestGenerateWithFallbacks(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	c.Xray.FallbackTag = "vless-reality"
	nodes, _ := parseSubscription(sampleSub(), parseOpts{})
	fb, _ := fallbackNode(Fallback{Name: "r", Link: "socks://proxy.example.com:1080"}, nil)
	env := Env{OutTags: map[string]string{"direct": "freedom", "vless-reality": "vless"}, InTags: map[string]bool{}, sockByTag: map[string]any{}}
	rs := RouteSet{VPN: Rules{Domains: []string{"domain:example.com"}}}
	r, x, err := generate(c, env, nodes, []Node{fb}, rs)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Routing struct {
			Rules     []map[string]any `json:"rules"`
			Balancers []map[string]any `json:"balancers"`
		} `json:"routing"`
	}
	json.Unmarshal(r, &doc)
	if doc.Routing.Balancers[0]["fallbackTag"] != fb.Tag {
		t.Errorf("fallbackTag балансировщика: %v", doc.Routing.Balancers[0]["fallbackTag"])
	}
	var xd struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	json.Unmarshal(x, &xd)
	port := -1
	for _, in := range xd.Inbounds {
		if in["tag"] == testTag(fb) {
			port = int(in["port"].(float64))
		}
	}
	if port != c.Xray.TestPortBase+len(nodes) {
		t.Errorf("тестовый порт резерва: %d", port)
	}
	if !strings.Contains(string(x), `"`+fb.Tag+`"`) || !strings.Contains(string(r), testTag(fb)) {
		t.Error("резерв должен быть в outbounds и в правилах проверки")
	}
	// без узлов подписок трафик VPN идёт прямо в резерв
	r, _, _ = generate(c, env, nil, []Node{fb}, rs)
	if !strings.Contains(string(r), `"outboundTag": "`+fb.Tag+`"`) {
		t.Errorf("без узлов должен использоваться резерв:\n%s", r)
	}
	// без резервов xsub — прежний запасной outbound
	r, _, _ = generate(c, env, nodes, nil, rs)
	if !strings.Contains(string(r), `"fallbackTag": "vless-reality"`) {
		t.Error("без резервов должен остаться fallback_tag из настроек")
	}
}

func TestFallbacksWithRealXray(t *testing.T) {
	xray, assets := os.Getenv("XSUB_TEST_XRAY"), os.Getenv("XSUB_TEST_DAT")
	if xray == "" {
		t.Skip("нет XSUB_TEST_XRAY")
	}
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.Bin, c.Xray.AssetDir, c.Xray.ConfDir = xray, assets, t.TempDir()
	c.Xray.RestartCmd = "true"
	writeConf(t, c.Xray.ConfDir, map[string]string{
		"01_log.json":       `{"log":{"loglevel":"warning"}}`,
		"04_outbounds.json": testOutboundsConf,
	})
	os.WriteFile(c.path("vpn.txt"), []byte("example.com\n"), 0o644)
	fbs, err := prepareFallbacks(c, []Fallback{{Import: "vless-reality"}, {Import: "backup-proxy"}, {Link: "http://u:p@proxy.example.com:3128"}})
	if err != nil {
		t.Fatal(err)
	}
	saveFallbacksFile(c, fbs)
	fnodes, warns := fallbackNodes(c, map[string]any{"mark": 255})
	if len(warns) > 0 {
		t.Fatal(warns)
	}
	good, bad := validateNodes(c, fnodes)
	if len(bad) > 0 || len(good) != 3 {
		t.Fatalf("Xray не принял резервы: %v", bad)
	}
	nodes, _ := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{sockopt: map[string]any{"mark": 255}})
	env, _ := scanEnv(c)
	if _, err := applyConfig(c, env, nodes, good, "тест"); err != nil {
		t.Fatal(err)
	}
	if _, err := applyConfig(c, env, nil, good, "только резервы"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(c.Xray.ConfDir, xsubFile))
	if !strings.Contains(string(b), good[0].Tag) {
		t.Error("в 07_xsub.json нет резерва")
	}
}

// Панели (например, Remnawave) при каждой выдаче меняют shortId и имена — тег узла не должен меняться.
func TestStableNodeTag(t *testing.T) {
	base := "vless://" + tUUID + "@nl.example.com:443?encryption=none&type=tcp&security=reality&sni=www.example.org&fp=firefox&pbk=" + tPBK
	a, err1 := parseLink(base+"&sid=8718c58d#NL 1", nil)
	b, err2 := parseLink(base+"&sid=ab&fp=chrome#NL 1 (осталось 5 ГБ)", nil)
	c, err3 := parseLink(strings.Replace(base, ":443", ":8443", 1)+"#NL 1", nil)
	d, err4 := parseLink(strings.Replace(base, "type=tcp", "type=xhttp&path=%2Fx", 1)+"#NL 1", nil)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		t.Fatal(err1, err2, err3, err4)
	}
	if a.Tag != b.Tag {
		t.Errorf("тег поменялся из-за shortId/имени: %s → %s", a.Tag, b.Tag)
	}
	if a.Tag == c.Tag || a.Tag == d.Tag {
		t.Error("разные порты и транспорты должны давать разные теги")
	}
}

// Свежая установка XKeen: 04_outbounds.json пустой (только комментарий), 05_routing.json ссылается
// на несуществующий vless-reality. xsub должен собрать рабочий конфиг без ручных правок.
func TestFreshXKeenConfigs(t *testing.T) {
	xray, assets := os.Getenv("XSUB_TEST_XRAY"), os.Getenv("XSUB_TEST_DAT")
	if xray == "" {
		t.Skip("нет XSUB_TEST_XRAY")
	}
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.Bin, c.Xray.AssetDir, c.Xray.ConfDir = xray, assets, t.TempDir()
	c.Xray.RestartCmd = "true"
	tunnel := func(tag string, port int, net string, sniff string) string {
		s := `{"protocol":"tunnel","port":` + fmt2(port) + `,"settings":{"allowedNetwork":"` + net + `","followRedirect":true},"tag":"` + tag + `"`
		if net == "udp" {
			s += `,"streamSettings":{"sockopt":{"tproxy":"tproxy"}}`
		}
		if sniff != "" {
			s += `,"sniffing":{"enabled":true,"routeOnly":true,"destOverride":[` + sniff + `]}`
		}
		return s + "}"
	}
	writeConf(t, c.Xray.ConfDir, map[string]string{
		"01_log.json":       `{"log":{"loglevel":"none"}}`,
		"02_dns.json":       "{\n// пример настройки\n}",
		"03_inbounds.json":  `{"inbounds":[` + tunnel("redirect", 1181, "tcp", `"http","tls"`) + "," + tunnel("tproxy", 1181, "udp", `"quic"`) + "," + tunnel("force-proxy-redirect", 1191, "tcp", "") + "," + tunnel("force-proxy-tproxy", 1191, "udp", "") + `]}`,
		"04_outbounds.json": "{\n// создайте файл\n}",
		"05_routing.json":   "// пример\n" + `{"routing":{"rules":[{"inboundTag":["force-proxy-redirect","force-proxy-tproxy"],"outboundTag":"vless-reality"},{"inboundTag":["redirect","tproxy"],"outboundTag":"direct"}]}}`,
		"06_policy.json":    `{"policy":{"levels":{"0":{"uplinkOnly":0,"downlinkOnly":0}}}}`,
	})
	os.WriteFile(c.path("vpn.txt"), []byte("example.com\n"), 0o644)
	nodes, _ := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{})
	env, _ := scanEnv(c)
	if _, err := applyConfig(c, env, nodes, nil, "свежий XKeen"); err != nil {
		t.Fatalf("конфиг свежего XKeen: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(c.Xray.ConfDir, routingFile))
	if !strings.Contains(string(b), "force-proxy-redirect") {
		t.Error("force-proxy должен идти через узлы")
	}
}

func fmt2(n int) string { return strconv.Itoa(n) }

func TestInterfaceFallback(t *testing.T) {
	tmpl := map[string]any{"mark": float64(100)}
	n, err := fallbackNode(Fallback{Name: "Keenetic WG", Interface: "nwg0"}, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if !isFallbackTag(n.Tag) {
		t.Errorf("тег резерва: %s", n.Tag)
	}
	if n.Name != "Keenetic WG" || n.Proto != ifaceProto || n.Address != "nwg0" {
		t.Errorf("%+v", n)
	}
	if nodeSummary(n) != "interface nwg0" {
		t.Errorf("описание: %q", nodeSummary(n))
	}
	if anyStr(n.Outbound["protocol"]) != "freedom" {
		t.Errorf("протокол: %v", n.Outbound["protocol"])
	}
	so := n.Outbound["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if so["interface"] != "nwg0" {
		t.Errorf("нет привязки к интерфейсу: %v", so)
	}
	if so["mark"] != float64(100) {
		t.Errorf("метка XKeen должна сохраняться, иначе трафик завернётся обратно: %v", so)
	}
	if ifaceOf(n.Outbound) != "nwg0" {
		t.Errorf("ifaceOf: %q", ifaceOf(n.Outbound))
	}

	// Тег зависит от интерфейса и не зависит от имени и метки.
	other, _ := fallbackNode(Fallback{Name: "другое имя", Interface: "ovpn_br0"}, nil)
	if other.Tag == n.Tag {
		t.Error("разные интерфейсы — разные теги")
	}
	same, _ := fallbackNode(Fallback{Name: "третье имя", Interface: "nwg0"}, nil)
	if same.Tag != n.Tag {
		t.Error("тот же интерфейс — тот же тег, иначе история проверок теряется")
	}

	for _, bad := range []string{"nwg0; rm -rf /", "интерфейс", "слишком-длинное-имя-интерфейса", ""} {
		if _, err := fallbackNode(Fallback{Interface: bad}, nil); err == nil {
			t.Errorf("%q не должно приниматься как интерфейс", bad)
		}
	}
}

func TestImportFreedomInterface(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"outbounds":[
	  {"tag":"wg-keenetic","protocol":"freedom","streamSettings":{"sockopt":{"interface":"nwg0","mark":100}}},
	  {"tag":"direct","protocol":"freedom"},
	  {"tag":"block","protocol":"blackhole"}]}`
	if err := os.WriteFile(filepath.Join(dir, "10_out.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := defaultConfig()
	c.Xray.ConfDir = dir

	// freedom с привязкой переносится как резерв-интерфейс, без привязки — не предлагается.
	out, err := prepareFallbacks(c, []Fallback{{Import: "wg-keenetic"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Interface != "nwg0" || out[0].Outbound != nil {
		t.Fatalf("%+v", out)
	}
	if out[0].Name != "wg-keenetic" {
		t.Errorf("имя: %q", out[0].Name)
	}

	a := &App{c: c}
	res := a.uiFallbacks()
	cands := res["imports"].([]ImportCandidate)
	var tags []string
	for _, c := range cands {
		tags = append(tags, c.Tag)
	}
	if strings.Join(tags, ",") != "wg-keenetic" {
		t.Fatalf("в кандидаты должен попасть только freedom с интерфейсом: %v", tags)
	}
	if cands[0].Summary != "interface nwg0" {
		t.Errorf("описание кандидата: %q", cands[0].Summary)
	}
	if res["interfaces"] == nil {
		t.Error("страница ждёт список интерфейсов роутера")
	}
}
