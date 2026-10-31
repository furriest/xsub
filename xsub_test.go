package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Только вымышленные данные: UUID и ключ сгенерированы случайно, адреса — example.com.
const (
	tUUID = "2d32250e-fb36-4495-bf21-07fa0b2e7f9d"
	tPBK  = "4oPjFhCGYBbtVD2aCoA4x3EULVckDGWQYjvci2tp6Jo"
)

func sampleSub() string {
	ssUser := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:secret"))
	ssLegacy := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw@ss2.example.com:8389"))
	lines := []string{
		"vless://" + tUUID + "@nl.example.com:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.example.org&fp=firefox&pbk=" + tPBK + "&sid=8718c58d#%F0%9F%87%B3%F0%9F%87%B1%20Netherlands",
		"vless://" + tUUID + "@de.example.com:8443?encryption=none&type=xhttp&security=reality&sni=www.example.org&pbk=" + tPBK + "&sid=ab&path=%2Fx&mode=auto#Germany%20xhttp",
		"vless://" + tUUID + "@ws.example.com:443?encryption=none&type=ws&security=tls&sni=ws.example.com&host=ws.example.com&path=%2Fws#WS",
		"vless://" + tUUID + "@ru.example.com:443?type=tcp&security=reality&sni=a.example&pbk=" + tPBK + "&sid=ab#%F0%9F%87%B7%F0%9F%87%BA%20Russia",
		"vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp#%D0%9E%D1%81%D1%82%D0%B0%D0%BB%D0%BE%D1%81%D1%8C%2010%20%D0%93%D0%91",
		"trojan://pa%40ss@tr.example.com:443?sni=tr.example.com&type=grpc&serviceName=svc#Trojan%20gRPC",
		"ss://" + ssUser + "@ss.example.com:8388#SS",
		"ss://" + ssLegacy + "#SS%20legacy",
		"ss://" + ssUser + "@ssp.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp#SS%20plugin",
		vmessLink(map[string]any{"v": "2", "ps": "VMess WS", "add": "vm.example.com", "port": "443", "id": tUUID, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "vm.example.com", "path": "/vm", "tls": "tls", "sni": "vm.example.com"}),
		vmessLink(map[string]any{"v": "2", "ps": "VMess legacy", "add": "old.example.com", "port": 443, "id": tUUID, "aid": 64, "net": "tcp"}),
		"hysteria2://pw@hy.example.com:443#HY2",
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
}

func TestParseSubscription(t *testing.T) {
	nodes, warns := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{
		sub: "test", exclude: regexp.MustCompile("(?i)🇷🇺|Russia"), sockopt: map[string]any{"mark": 255}, maxNodes: 60,
	})
	var names []string
	for _, n := range nodes {
		names = append(names, n.Proto+":"+n.Name)
	}
	want := []string{"vless:🇳🇱 Netherlands", "vless:Germany xhttp", "vless:WS", "trojan:Trojan gRPC", "ss:SS", "ss:SS legacy", "vmess:VMess WS", "hysteria2:HY2"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("узлы:\n%v\nожидалось:\n%v\nпредупреждения: %v", names, want, warns)
	}
	joined := strings.Join(warns, "\n")
	for _, w := range []string{"плагин obfs-local", "alterId", "информационных записей (не серверов): 1"} {
		if !strings.Contains(joined, w) {
			t.Errorf("нет предупреждения %q в:\n%s", w, joined)
		}
	}
	for _, w := range warns {
		if strings.Contains(w, tUUID) || strings.Contains(w, "pa%40ss") {
			t.Errorf("в предупреждении утёк секрет: %s", w)
		}
	}
	tr := nodes[3].Outbound["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if tr["password"] != "pa@ss" {
		t.Errorf("пароль trojan: %v", tr["password"])
	}
	ss := nodes[5].Outbound["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if ss["method"] != "aes-256-gcm" || ss["password"] != "pw" || ss["address"] != "ss2.example.com" {
		t.Errorf("ss legacy: %v", ss)
	}

	inc, _ := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{include: regexp.MustCompile("^WS$")})
	if len(inc) != 1 || inc[0].Name != "WS" {
		t.Errorf("include: %v", inc)
	}
}

func TestParseList(t *testing.T) {
	r, _, errs := parseListFull("Example.COM # комм\n=a.b.c\n*.x.org\nregexp:^Ab$\next:geosite_itdog.dat:youtube\n1.2.3.0/24\n2001:db8::1\nip:geoip:ru\n\n# только комментарий\nплохо!\n")
	d, ip := r.Domains, r.IPs
	want := []string{"domain:example.com", "full:a.b.c", "domain:x.org", "regexp:^Ab$", "ext:geosite_itdog.dat:youtube"}
	if strings.Join(d, ",") != strings.Join(want, ",") {
		t.Fatalf("домены: %v", d)
	}
	if strings.Join(ip, ",") != "1.2.3.0/24,2001:db8::1,geoip:ru" {
		t.Fatalf("ip: %v", ip)
	}
	if len(errs) != 1 {
		t.Fatalf("ошибки: %v", errs)
	}
}

func TestStripComments(t *testing.T) {
	in := "// x\n{\"a\": \"http://b//c\", /* y */ \"d\": 1}\n"
	got := string(stripJSONComments([]byte(in)))
	if !strings.Contains(got, `"http://b//c"`) || strings.Contains(got, "y */") {
		t.Fatalf("%q", got)
	}
}

func TestUserInfo(t *testing.T) {
	h := http.Header{}
	h.Set("subscription-userinfo", "upload=100; download=200; total=1000; expire=1767225600")
	ui := parseUserInfo(h)
	if ui == nil || ui.Upload != 100 || ui.Download != 200 || ui.Total != 1000 || ui.Expire != 1767225600 {
		t.Fatalf("%+v", ui)
	}
}

func writeConf(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnvDetection(t *testing.T) {
	c := defaultConfig()
	c.Xray.ConfDir = t.TempDir()
	c.Xray.FallbackTag = "nope"
	writeConf(t, c.Xray.ConfDir, map[string]string{
		"03_inbounds.json":  `{"inbounds":[{"tag":"redirect","port":1,"protocol":"dokodemo-door"}]}`,
		"04_outbounds.json": `// комментарий` + "\n" + `{"outbounds":[{"tag":"my","protocol":"vless","streamSettings":{"sockopt":{"mark":77}}},{"tag":"bh","protocol":"blackhole"}]}`,
	})
	env, err := scanEnv(c)
	if err != nil {
		t.Fatal(err)
	}
	if tag, own := env.directTag(c); tag != ownDirect || !own {
		t.Errorf("direct: %s %v", tag, own)
	}
	if env.fallbackTag(c) != "" {
		t.Error("несуществующий fallback должен игнорироваться")
	}
	so, _ := json.Marshal(env.Sockopt(c))
	if string(so) != `{"mark":77}` {
		t.Errorf("sockopt: %s", so)
	}
	nodes, _ := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{maxNodes: 2})
	r, x, err := generate(c, env, nodes, nil, RouteSet{VPN: Rules{Domains: []string{"domain:example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(x), `"tag": "xsub-direct"`) || !strings.Contains(string(r), `"outboundTag": "xsub-direct"`) {
		t.Errorf("нет собственного direct:\n%s\n%s", r, x)
	}
	if strings.Contains(string(r), "force-proxy") {
		t.Error("правило для несуществующих force-proxy входов")
	}
	// без узлов и без запасного — VPN-правил нет, всё напрямую
	r, _, _ = generate(c, env, nil, nil, RouteSet{VPN: Rules{Domains: []string{"domain:example.com"}}})
	if strings.Contains(string(r), "example.com") {
		t.Errorf("без узлов VPN-правила не нужны:\n%s", r)
	}
	// конфликт с чужой секцией api
	writeConf(t, c.Xray.ConfDir, map[string]string{"02_api.json": `{"api":{"tag":"api"}}`})
	env, _ = scanEnv(c)
	if _, _, err := generate(c, env, nodes, nil, RouteSet{}); err == nil || !strings.Contains(err.Error(), "02_api.json") {
		t.Errorf("ожидалась ошибка про api: %v", err)
	}
}

func TestLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte(`{"password":"x", "subscription": {"url": "https://example.com/sub", "user_agent": "Happ/1.0", "interval_hours": 3, "exclude": "(?i)ru"}}`), 0o600)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SubIntervalHours != 3 {
		t.Errorf("интервал: %d", c.SubIntervalHours)
	}
	subs, err := loadSubs(c)
	if err != nil || len(subs) != 1 || subs[0].URL != "https://example.com/sub" || subs[0].UserAgent != "Happ/1.0" {
		t.Fatalf("%v %+v", err, subs)
	}
	if _, err := os.Stat(filepath.Join(dir, subsFile)); err != nil {
		t.Fatal("subscriptions.json не создан")
	}
	if err := validateSubs([]Subscription{{URL: "ftp://x"}}); err == nil {
		t.Error("ftp-ссылка должна отклоняться")
	}
	if err := validateSubs([]Subscription{{URL: "https://x", Exclude: "("}}); err == nil {
		t.Error("битое регулярное выражение должно отклоняться")
	}
}

// Проверка настоящим xray: XSUB_TEST_XRAY=путь, XSUB_TEST_DAT=папка с geosite_itdog.dat.
func TestWithRealXray(t *testing.T) {
	xray, assets := os.Getenv("XSUB_TEST_XRAY"), os.Getenv("XSUB_TEST_DAT")
	if xray == "" {
		t.Skip("нет XSUB_TEST_XRAY")
	}
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.Bin, c.Xray.AssetDir, c.Xray.ConfDir = xray, assets, t.TempDir()
	c.Xray.RestartCmd = "true"
	c.Xray.FallbackTag = "vless-reality"
	writeConf(t, c.Xray.ConfDir, map[string]string{
		"01_log.json":      `{"log":{"loglevel":"warning"}}`,
		"03_inbounds.json": `{"inbounds":[{"tag":"redirect","port":61219,"protocol":"dokodemo-door","settings":{"network":"tcp","followRedirect":true}},{"tag":"force-proxy-redirect","port":61220,"protocol":"dokodemo-door","settings":{"network":"tcp","followRedirect":true}}]}`,
		"04_outbounds.json": `{"outbounds":[{"tag":"vless-reality","protocol":"vless","settings":{"vnext":[{"address":"example.org","port":443,"users":[{"id":"` + tUUID + `","encryption":"none"}]}]},
			"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"a.example","fingerprint":"chrome","publicKey":"` + tPBK + `","shortId":"ab"},"sockopt":{"mark":255}}},
			{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}`,
		"05_routing.json": "// пример\n" + `{"routing":{"rules":[{"inboundTag":["force-proxy-redirect"],"outboundTag":"vless-reality"}]}}`,
	})
	os.WriteFile(c.path("vpn.txt"), []byte(defaultVPN), 0o644)
	os.WriteFile(c.path("direct.txt"), []byte("ru-board.com\n"), 0o644)
	gb, _ := marshal([]Group{{ID: "g1", Name: "NL", Filter: "(?i)netherlands"}, {ID: "g2", Name: "Пусто", Filter: "^нет$"}})
	os.WriteFile(c.path(groupsFile), gb, 0o644)
	os.WriteFile(c.path(groupListName("g1")), []byte("ext:geosite_itdog.dat:youtube\n"), 0o644)
	os.WriteFile(c.path(groupListName("g2")), []byte("empty.example\n"), 0o644)

	nodes, _ := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{sockopt: map[string]any{"mark": 255}})
	env, _ := scanEnv(c)
	if managed(c) {
		t.Fatal("до первого применения xsub не должен считаться управляющим")
	}
	changed, err := applyConfig(c, env, nodes, nil, "тест")
	if err != nil || !changed {
		t.Fatalf("applyConfig: changed=%v err=%v", changed, err)
	}
	if !managed(c) {
		t.Fatal("исходные файлы не сохранены")
	}
	if k := os.Getenv("XSUB_KEEP"); k != "" {
		os.MkdirAll(k, 0o755)
		fs, _ := filepath.Glob(filepath.Join(c.Xray.ConfDir, "*.json"))
		for _, f := range fs {
			b, _ := os.ReadFile(f)
			os.WriteFile(filepath.Join(k, filepath.Base(f)), b, 0o644)
		}
	}
	if changed, err := applyConfig(c, env, nodes, nil, "повтор"); err != nil || changed {
		t.Fatalf("повторное применение: changed=%v err=%v", changed, err)
	}
	if _, err := applyConfig(c, env, nil, nil, "без узлов"); err != nil {
		t.Fatalf("без узлов: %v", err)
	}
	os.WriteFile(c.path("vpn.txt"), []byte("плохо но!!\n"), 0o644)
	if _, err := applyConfig(c, env, nodes, nil, "битый список"); err == nil {
		t.Fatal("битый список должен давать ошибку")
	}
	if err := restoreOriginals(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(c.Xray.ConfDir, routingFile))
	if !strings.HasPrefix(string(b), "// пример") {
		t.Fatalf("05_routing.json не восстановлен: %s", b)
	}
	if _, err := os.Stat(filepath.Join(c.Xray.ConfDir, xsubFile)); !os.IsNotExist(err) {
		t.Fatal("07_xsub.json не удалён")
	}
}

func TestLogRotation(t *testing.T) {
	dir := t.TempDir()
	l := &Logger{path: filepath.Join(dir, "x.log"), maxSize: 1024}
	for i := 0; i < 200; i++ {
		l.Printf("строка %d %s", i, strings.Repeat("x", 40))
	}
	cur, _ := os.Stat(l.path)
	old, _ := os.Stat(l.path + ".old")
	if cur == nil || old == nil || cur.Size() > 1200 || old.Size() > 1200 {
		t.Fatalf("ротация не работает: %v %v", cur, old)
	}
	if got := l.Tail(5); len(got) != 5 || !strings.Contains(got[4], "строка 199") {
		t.Fatalf("хвост в памяти: %v", got)
	}
	m := &Logger{maxSize: 1024} // только в памяти
	m.Printf("тест")
	if len(m.Tail(10)) != 1 {
		t.Fatal("журнал в памяти")
	}
}

func TestDecodeB64Variants(t *testing.T) {
	want := "vless://x@example.com:443?type=tcp#узел~1"
	cases := map[string]string{
		"обычный":           base64.StdEncoding.EncodeToString([]byte(want)),
		"без дополнения":    base64.RawStdEncoding.EncodeToString([]byte(want)),
		"url-safe":          base64.URLEncoding.EncodeToString([]byte(want)),
		"url-safe без доп.": base64.RawURLEncoding.EncodeToString([]byte(want)),
	}
	for name, enc := range cases {
		if got, ok := decodeB64(enc); !ok || got != want {
			t.Errorf("%s: ok=%v %q", name, ok, got)
		}
		// Панели переносят строки в теле подписки — пробелы и переводы строк не мешают.
		split := enc[:len(enc)/2] + "\n" + enc[len(enc)/2:]
		if got, ok := decodeB64(split); !ok || got != want {
			t.Errorf("%s с переносом: ok=%v %q", name, ok, got)
		}
	}
	for _, bad := range []string{"", "это не base64!!", "vless://example.com"} {
		if _, ok := decodeB64(bad); ok {
			t.Errorf("%q не должно разбираться как base64", bad)
		}
	}
}

func TestUpdatePackagePick(t *testing.T) {
	// Имена из SHA256SUMS, который делает scripts/build.sh.
	sums := "aaa  install.sh\n" +
		"b1b1  xsub_mipsel.ipk\n" +
		"C2C2  xsub_aarch64.ipk\n" +
		"e4e4  xsub_x86_64.ipk\n" +
		"d3d3  xsub-0.6.0-mipsel\n"
	if got := sumFor(sums, "xsub_mipsel.ipk"); got != "b1b1" {
		t.Errorf("mipsel: %q", got)
	}
	if got := sumFor(sums, "xsub_aarch64.ipk"); got != "c2c2" {
		t.Errorf("регистр должен приводиться к нижнему: %q", got)
	}
	if got := sumFor(sums, "xsub_armv7.ipk"); got != "" {
		t.Errorf("отсутствующий файл: %q", got)
	}
	// Голое имя не должно совпасть с похожим: ищем точное совпадение.
	if got := sumFor(sums, "mipsel.ipk"); got != "" {
		t.Errorf("частичное совпадение недопустимо: %q", got)
	}
	// Имена архитектур должны совпадать с теми, что собирает scripts/build.sh.
	want := map[string]string{"amd64": "x86_64", "arm64": "aarch64", "mipsle": "mipsel", "mips": "mips", "arm": "armv7"}
	for goarch, arch := range want {
		if got := ipkArchOf(goarch); got != arch {
			t.Errorf("%s → %q, ожидалось %q", goarch, got, arch)
		}
		if sumFor(sums, "xsub_"+arch+".ipk") == "" && arch != "mips" && arch != "armv7" {
			t.Errorf("в тестовом SHA256SUMS нет пакета для %s", arch)
		}
	}
	if got := ipkArchOf("riscv64"); got != "" {
		t.Errorf("для архитектуры без пакетов должно быть пусто: %q", got)
	}
}
