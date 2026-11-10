package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// unixPerms — права файлов проверяемы. На Windows их нет, а тесты там
// запускают при разработке.
var unixPerms = runtime.GOOS != "windows"

func newTestApp(t *testing.T) *App {
	t.Helper()
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Password = "secret1"
	c.Xray.ConfDir = t.TempDir()
	c.Xray.AssetDir = os.Getenv("XSUB_TEST_DAT")
	a, err := newApp(c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestGroupsGenerate(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	nodes, _ := parseSubscription(sampleSub(), parseOpts{})
	gs := []Group{{ID: "g1", Name: "Нидерланды", Filter: "(?i)netherlands"}, {ID: "g2", Name: "Пусто", Filter: "^нет такого$"}}
	defs := targetDefs(c, nodes, gs)
	if len(defs) != 3 || len(defs[1].Tags) != 1 || !defs[2].Empty || defs[1].ProbePort != c.Xray.ProbePort+1 {
		t.Fatalf("цели: %+v", defs)
	}
	rs := RouteSet{
		VPN:    Rules{Domains: []string{"domain:example.com"}},
		Groups: []GroupRules{{Group: gs[0], Rules: Rules{Domains: []string{"domain:youtube.com"}}}, {Group: gs[1], Rules: Rules{Domains: []string{"domain:empty.example"}}}},
	}
	env := Env{OutTags: map[string]string{"direct": "freedom"}, InTags: map[string]bool{}, sockByTag: map[string]any{}}
	r, x, err := generate(c, env, nodes, nil, rs)
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
	if len(doc.Routing.Balancers) != 2 {
		t.Fatalf("балансировщики: %v", doc.Routing.Balancers)
	}
	find := func(dom string) string {
		for _, rl := range doc.Routing.Rules {
			if d, ok := rl["domain"].([]any); ok && d[0] == dom {
				return anyStr(rl["balancerTag"])
			}
		}
		return "?"
	}
	if find("domain:youtube.com") != "xsub-g1" || find("domain:empty.example") != "xsub" || find("domain:example.com") != "xsub" {
		t.Errorf("правила групп: youtube→%s empty→%s vpn→%s", find("domain:youtube.com"), find("domain:empty.example"), find("domain:example.com"))
	}
	if !strings.Contains(string(x), `"xsub-probe-g1"`) || strings.Contains(string(x), `"xsub-probe-g2"`) {
		t.Errorf("входы проверки групп:\n%s", x)
	}
	// порядок: группы раньше общего списка VPN
	if strings.Index(string(r), "youtube.com") > strings.Index(string(r), `"domain:example.com"`) {
		t.Error("правила группы должны идти раньше списка VPN")
	}
}

func TestRemoteParse(t *testing.T) {
	r, skipped := parseRemote("# заголовок\nexample.com\nserver=/blocked.example/127.0.0.1#5353\nipset=/x.example/vpn\n10.0.0.0/8\n<html>\n")
	if strings.Join(r.Domains, ",") != "domain:example.com,domain:blocked.example,domain:x.example" || len(r.IPs) != 1 || skipped != 1 {
		t.Fatalf("%+v skipped=%d", r, skipped)
	}
	_, remotes, errs := parseListFull("https://example.com/list.lst\nexample.org\n")
	if len(remotes) != 1 || len(errs) != 0 {
		t.Fatalf("%v %v", remotes, errs)
	}
}

func TestReadRoutingRemote(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	os.WriteFile(c.path("vpn.txt"), []byte("https://lists.example/a.lst\nhttps://lists.example/b.lst\nown.example\n"), 0o600)
	os.MkdirAll(c.path("remote"), 0o700)
	os.WriteFile(remotePath(c, "https://lists.example/a.lst"), []byte("remote.example\n1.2.3.0/24\n"), 0o600)
	rs, errs, err := readRouting(c)
	if err != nil || len(errs) > 0 {
		t.Fatal(err, errs)
	}
	if strings.Join(rs.VPN.Domains, ",") != "domain:own.example,domain:remote.example" || len(rs.VPN.IPs) != 1 {
		t.Errorf("%+v", rs.VPN)
	}
	if len(rs.Warnings) != 1 || !strings.Contains(rs.Warnings[0], "b.lst") {
		t.Errorf("предупреждения: %v", rs.Warnings)
	}
}

func TestCheckRoute(t *testing.T) {
	dat := os.Getenv("XSUB_TEST_DAT")
	if dat == "" {
		t.Skip("нет XSUB_TEST_DAT")
	}
	a := newTestApp(t)
	c := a.c
	os.WriteFile(c.path("direct.txt"), []byte("ru-board.com\n=only.example\n"), 0o600)
	os.WriteFile(c.path("vpn.txt"), []byte(defaultVPN), 0o600)
	b, _ := marshal([]Group{{ID: "g1", Name: "YouTube", Filter: ""}})
	os.WriteFile(c.path(groupsFile), b, 0o600)
	os.WriteFile(c.path(groupListName("g1")), []byte("ext:geosite_itdog.dat:youtube\n"), 0o600)

	cases := map[string]string{
		"https://forum.ru-board.com/topic": "direct",
		"only.example":                     "direct",
		"sub.only.example":                 "direct",
		"www.youtube.com":                  "group",
		"instagram.com":                    "vpn",
		"149.154.167.99":                   "vpn",
		"ya.ru":                            "direct",
	}
	for in, want := range cases {
		res := a.checkTarget(in)
		if res.Route != want {
			t.Errorf("%s: %s (%s / %s), ожидалось %s; заметки: %v", in, res.Route, res.List, res.Rule, want, res.Notes)
		}
	}
	if res := a.checkTarget("sub.only.example"); res.Target != "Напрямую (ни в одном списке)" {
		t.Errorf("=only.example не должен ловить поддомены: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dat, "geoip.dat")); err == nil {
		if ok, err := matchIPRule(c, net.ParseIP("77.88.8.8"), "geoip:ru"); err != nil || !ok {
			t.Errorf("geoip:ru для 77.88.8.8: %v %v", ok, err)
		}
	}
}

func TestVersionsAndAccess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.3.1", "0.4.0", true}, {"0.4.0", "0.4.0", false}, {"0.10.0", "0.9.9", false}, {"dev", "0.4.0", false}, {"0.4.0", "v0.4.1", true}} {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%s,%s)=%v", c.a, c.b, got)
		}
	}
	for ip, want := range map[string]bool{"192.168.1.5": true, "10.1.2.3": true, "127.0.0.1": true, "100.64.1.1": true, "8.8.8.8": false, "2a00:1450::1": false, "fd00::1": true} {
		if isPrivate(net.ParseIP(ip)) != want {
			t.Errorf("isPrivate(%s) != %v", ip, want)
		}
	}
	l := &limiter{fails: map[string][]time.Time{}}
	for i := 0; i < maxFails; i++ {
		if l.blocked("1.2.3.4") {
			t.Fatal("заблокировано раньше времени")
		}
		l.fail("1.2.3.4")
	}
	if !l.blocked("1.2.3.4") || l.blocked("5.6.7.8") {
		t.Fatal("ограничение попыток работает неверно")
	}
}

func TestBackupRestore(t *testing.T) {
	a := newTestApp(t)
	c := a.c
	cfg := "{\n  // комментарий\n  \"password\": \"secret1\"\n}\n"
	os.WriteFile(c.path("config.json"), []byte(cfg), 0o600)
	os.WriteFile(c.path("vpn.txt"), []byte("a.example\n"), 0o600)
	os.WriteFile(c.path("group-g1.txt"), []byte("old.example\n"), 0o600)
	os.WriteFile(c.path("cache.bin"), []byte("x"), 0o600)
	bk := a.backup()
	if bk.Files["config.json"] != cfg || bk.Files["vpn.txt"] == "" || bk.Files["cache.bin"] != "" {
		t.Fatalf("копия: %v", bk.Files)
	}
	bad := bk
	bad.Files = map[string]string{"config.json": cfg, "../evil": "x"}
	if err := a.restore(bad); err == nil {
		t.Fatal("лишний файл должен отклоняться")
	}
	delete(bk.Files, "group-g1.txt")
	bk.Files["vpn.txt"] = "b.example\n"
	if err := a.restoreFilesOnly(bk); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(c.path("vpn.txt")); string(b) != "b.example\n" {
		t.Errorf("vpn.txt: %q", b)
	}
	if _, err := os.Stat(c.path("group-g1.txt")); !os.IsNotExist(err) {
		t.Error("список удалённой группы должен удаляться")
	}
}

func TestSettingsValidation(t *testing.T) {
	a := newTestApp(t)
	var s UISettings
	s.SubIntervalHours, s.MaxNodes = 6, 60
	s.Watch.IntervalSec, s.Watch.FailsToSwitch = 60, 2
	s.Watch.TestBytes = 4 << 10
	s.Watch.CheckURLs = []string{"https://ok.example"}
	if err := a.validateSettings(&s); err == nil {
		t.Error("проверочная загрузка 4 КБ должна отклоняться")
	}
	s.Watch.TestBytes = 32 << 10
	s.Watch.CheckURLs = []string{"ftp://x"}
	if err := a.validateSettings(&s); err == nil {
		t.Error("ftp-адрес проверки должен отклоняться")
	}
	s.Watch.CheckURLs = []string{" https://www.instagram.com/ ", ""}
	s.Telegram.Token = "bad"
	if err := a.validateSettings(&s); err == nil {
		t.Error("неверный токен должен отклоняться")
	}
	s.Telegram.Token = "123456:" + strings.Repeat("A", 30)
	if err := a.validateSettings(&s); err != nil || len(s.Watch.CheckURLs) != 1 || s.Password != "secret1" {
		t.Errorf("%v %+v", err, s.Watch)
	}
}

func TestGeoSiteParse(t *testing.T) {
	dat := os.Getenv("XSUB_TEST_DAT")
	if dat == "" {
		t.Skip("нет XSUB_TEST_DAT")
	}
	c := defaultConfig()
	c.Xray.AssetDir = dat
	d, err := geoSite(c, "geosite_itdog.dat", "telegram")
	if err != nil || len(d) == 0 {
		t.Fatalf("%v %d", err, len(d))
	}
	if _, err := geoSite(c, "geosite_itdog.dat", "нет-такой"); err == nil {
		t.Error("несуществующая категория должна давать ошибку")
	}
}

func TestBackgroundSchedule(t *testing.T) {
	if q := bgQuota(30, time.Minute, 30*time.Minute); q != 1 {
		t.Errorf("30 узлов за 30 мин при тике 1 мин: %d", q)
	}
	if q := bgQuota(90, time.Minute, 30*time.Minute); q != 3 {
		t.Errorf("90 узлов: %d", q)
	}
	if q := bgQuota(3, 15*time.Second, 1440*time.Minute); q != 1 {
		t.Errorf("минимум один: %d", q)
	}
	now := time.Now()
	mk := func(tag string, ago time.Duration) *NodeState {
		st := newStats()
		if ago > 0 {
			st.LastTest = now.Add(-ago)
		}
		return &NodeState{Node: Node{Tag: tag}, Stats: st}
	}
	nodes := []*NodeState{mk("a", 0), mk("fresh", 5*time.Minute), mk("old", 40*time.Minute), mk("active", 0), mk("older", 50*time.Minute)}
	due := pickDue(nodes, map[string]bool{"active": true}, now, 30*time.Minute, time.Minute)
	if len(due) != 1 || due[0].Tag != "a" {
		t.Fatalf("первым должен идти ни разу не проверенный: %v", due)
	}
	due = pickDue(nodes, map[string]bool{"active": true}, now, 10*time.Minute, time.Minute)
	var tags []string
	for _, n := range due {
		tags = append(tags, n.Tag)
	}
	// 4 запасных за 10 мин при тике 1 мин → квота 1
	if strings.Join(tags, ",") != "a" {
		t.Fatalf("%v", tags)
	}
	due = pickDue(nodes[1:], map[string]bool{"active": true}, now, 2*time.Minute, time.Minute)
	tags = nil
	for _, n := range due {
		tags = append(tags, n.Tag)
	}
	// квота 2: самые давние первыми, «fresh» (5 мин) тоже просрочен при цикле 2 мин
	if strings.Join(tags, ",") != "older,old" {
		t.Fatalf("%v", tags)
	}
}

func TestTestURL(t *testing.T) {
	c := defaultConfig()
	if c.Watch.TestBytes != 32768 || testURL(c) != "https://speed.cloudflare.com/__down?bytes=32768" {
		t.Fatalf("по умолчанию: %d %s", c.Watch.TestBytes, testURL(c))
	}
	c.Watch.TestBytes = 24 << 10
	c.Watch.TestURL = "https://example.com/blob"
	if testURL(c) != "https://example.com/blob" {
		t.Fatalf("без {bytes} адрес не меняется: %s", testURL(c))
	}
}

func TestFasterNode(t *testing.T) {
	mk := func(tag string, ms int, ok bool, score float64) *NodeState {
		st := newStats()
		st.Score = score
		if ok {
			st.LastOK = time.Now()
		} else {
			st.LastFail = time.Now()
		}
		return &NodeState{Node: Node{Tag: tag, Name: tag}, LatencyMs: ms, Stats: st}
	}
	c := defaultConfig()
	c.Watch.SwitchFasterMs = 200
	w := newWatcher(c)
	w.nodes = []*NodeState{
		mk("cur", 800, true, 0.95),
		mk("fast", 500, true, 0.95),  // быстрее на 300 — подходит
		mk("near", 700, true, 0.95),  // быстрее всего на 100 — мало
		mk("flaky", 100, true, 0.30), // быстрый, но ненадёжный
		mk("dead", 50, false, 0.95),  // последняя проверка загрузкой не прошла
		mk("cold", 60, true, 0.95),   // быстрее всех — проверим исключения на нём
	}
	w.nodes[5].BadUntil = time.Now().Add(time.Minute) // «залип» — не берём
	tg := &Target{Active: "cur"}
	if n := w.faster(tg); n == nil || n.Tag != "fast" {
		t.Fatalf("ожидался fast: %v", n)
	}
	tg.Pinned = true
	if n := w.faster(tg); n != nil {
		t.Fatalf("вручную выбранный узел не меняем: %s", n.Tag)
	}
	tg.Pinned = false
	w.nodes[0].LatencyMs = -1
	if n := w.faster(tg); n != nil {
		t.Fatalf("без задержки текущего сравнивать не с чем: %s", n.Tag)
	}
	w.nodes[0].LatencyMs = 800
	c.Watch.SwitchFasterMs = 0
	if n := w.faster(tg); n != nil {
		t.Fatalf("при 0 переход выключен: %s", n.Tag)
	}
	c.Watch.SwitchFasterMs = 200
	tg.Active = fbPrefix + "abc"
	if n := w.faster(tg); n != nil {
		t.Fatalf("с резерва уходим только по возврату: %s", n.Tag)
	}
	tg.Active = "cur"
	tg.tags = map[string]bool{"cur": true, "near": true}
	if n := w.faster(tg); n != nil {
		t.Fatalf("узлы не из группы не годятся: %s", n.Tag)
	}
}

func TestNoNetReportedOnce(t *testing.T) {
	w := newWatcher(defaultConfig())
	if !w.setNoNet(true) {
		t.Fatal("о пропаже связи нужно сообщить")
	}
	if w.setNoNet(true) {
		t.Fatal("пока связи нет, сообщать каждый тик не нужно")
	}
	if !w.setNoNet(false) {
		t.Fatal("о возвращении связи нужно сообщить")
	}
	if w.setNoNet(false) {
		t.Fatal("в обычном состоянии сообщать нечего")
	}
}

func TestSameHost(t *testing.T) {
	c := defaultConfig()
	c.UIAllowHosts = []string{"xsub.home"}
	ok := []string{"192.168.1.1:8099", "10.0.0.5", "[fd00::1]:8099", "localhost:8099",
		"my.keenetic.net", "router.lan", "keenetic.local", "XSUB.HOME:8099", ""}
	bad := []string{"evil.example.com:8099", "xsub.attacker.ru", "rebind.nip.io:8099"}
	for _, h := range ok {
		if !sameHost(c, &http.Request{Host: h}) {
			t.Errorf("%q должен пускаться", h)
		}
	}
	for _, h := range bad {
		if sameHost(c, &http.Request{Host: h}) {
			t.Errorf("%q пускать нельзя", h)
		}
	}
}

func TestWriteAtomicMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	if err := writeAtomicMode(p, []byte("один"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicMode(p, []byte("два"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "два" {
		t.Fatalf("%q %v", b, err)
	}
	fi, err := os.Stat(p)
	if err != nil || (unixPerms && fi.Mode().Perm() != 0o600) {
		t.Fatalf("права %v %v", fi.Mode().Perm(), err)
	}
	// Временных файлов после себя не оставляем.
	es, _ := os.ReadDir(dir)
	if len(es) != 1 {
		var names []string
		for _, e := range es {
			names = append(names, e.Name())
		}
		t.Fatalf("в каталоге лишние файлы: %v", names)
	}
}

func TestStatsSurviveRestart(t *testing.T) {
	c := defaultConfig()
	c.Watch.StatsFile = filepath.Join(t.TempDir(), "stats.json")
	now := time.Now()

	w := newWatcher(c)
	w.stats["node-aaa"] = newStats()
	for i := 0; i < 5; i++ {
		w.stats["node-aaa"].record(true, now.Add(-time.Duration(i)*slotDur))
	}
	w.stats["node-bbb"] = newStats()
	w.stats["node-bbb"].record(false, now)
	w.saveStats()

	// Новый процесс: тот же файл, статистика на месте.
	w2 := newWatcher(c)
	got := w2.stats["node-aaa"]
	if got == nil || got.OK != 5 || len(got.Slots) != 5 {
		t.Fatalf("%+v", got)
	}
	if b := w2.stats["node-bbb"]; b == nil || b.Fail != 1 {
		t.Fatalf("%+v", b)
	}
	// Seen в файл не пишется — иначе первая же чистка сочла бы узлы сиротами.
	w2.dropOrphans(time.Now())
	if len(w2.stats) != 2 {
		t.Fatalf("после чистки сирот осталось %d", len(w2.stats))
	}

	// Протухшая копия не поднимается: за сутки засечки вытесняются целиком.
	b, _ := json.Marshal(statsDump{At: now.Add(-25 * time.Hour), Nodes: w.stats})
	if err := os.WriteFile(c.Watch.StatsFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if w3 := newWatcher(c); len(w3.stats) != 0 {
		t.Fatalf("старая копия не должна подниматься: %d", len(w3.stats))
	}

	// Без файла — просто пустая статистика, без ошибок.
	c.Watch.StatsFile = ""
	if w4 := newWatcher(c); len(w4.stats) != 0 {
		t.Fatal("с выключенным сохранением статистика должна быть пустой")
	}
}

// Сторож читают и пишут сразу несколько горутин: тик, веб-страница, применение
// подписки, сохранение истории. Тест нужен прежде всего для go test -race в CI —
// без нагрузки детектор гонок ничего не увидит.
func TestWatcherConcurrent(t *testing.T) {
	c := defaultConfig()
	c.Watch.StatsFile = filepath.Join(t.TempDir(), "stats.json")
	w := newWatcher(c)

	mkNodes := func(n int) []Node {
		var out []Node
		for i := 0; i < n; i++ {
			out = append(out, Node{
				Tag: fmt.Sprintf("node-%02d", i), Name: fmt.Sprintf("узел %d", i),
				Proto: "vless", Address: "example.com", Port: 443,
			})
		}
		return out
	}
	groups := []Group{{ID: "g1", Name: "группа", Filter: "узел [0-4]"}}
	nodes := mkNodes(12)
	w.setNodes(nodes, mkNodes(2)[:1], targetDefs(c, nodes, groups))

	done := make(chan struct{})
	var wg sync.WaitGroup
	run := func(f func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				f(i)
			}
		}()
	}

	run(func(i int) { w.record(fmt.Sprintf("node-%02d", i%12), i%3 != 0) }) // тик сторожа
	run(func(int) { _ = w.status() })                                       // опрос веб-страницы
	run(func(i int) {                                                       // обновление подписки
		ns := mkNodes(10 + i%5)
		w.setNodes(ns, nil, targetDefs(c, ns, groups))
	})
	run(func(int) { w.saveStats() })
	run(func(i int) { w.setNoNet(i%2 == 0) })
	run(func(i int) {
		if n := w.node(fmt.Sprintf("node-%02d", i%12)); n != nil {
			w.mu.Lock()
			n.LatencyMs = i % 500
			w.mu.Unlock()
		}
	})
	run(func(int) {
		for _, tg := range w.allTargets() {
			w.mu.Lock()
			addSlot(&tg.Slots, true, time.Now())
			_ = w.faster(tg)
			w.mu.Unlock()
		}
	})

	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()

	if len(w.status().Nodes) == 0 {
		t.Fatal("узлы пропали")
	}
}

func TestBisectNodes(t *testing.T) {
	mk := func(names ...string) []Node {
		var out []Node
		for _, n := range names {
			out = append(out, Node{Tag: "node-" + n, Name: n, Outbound: map[string]any{"tag": "node-" + n}})
		}
		return out
	}
	nodes := mk("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l")

	// Проверка набора: падает, если в нём есть «плохой» узел.
	runs := 0
	tester := func(broken map[string]bool) func([]Node) error {
		return func(ns []Node) error {
			runs++
			for _, n := range ns {
				if broken[n.Name] {
					return fmt.Errorf("плохой узел > unsupported transport\nвторая строка")
				}
			}
			return nil
		}
	}

	// Все узлы хорошие — один запуск.
	runs = 0
	good, bad := bisectNodes(nodes, tester(nil))
	if len(good) != 12 || len(bad) != 0 || runs != 1 {
		t.Fatalf("хороший набор: good=%d bad=%v запусков=%d", len(good), bad, runs)
	}

	// Один плохой: порядок сохраняется, запусков заметно меньше, чем узлов.
	runs = 0
	good, bad = bisectNodes(nodes, tester(map[string]bool{"g": true}))
	if len(bad) != 1 || !strings.Contains(bad[0], "g: Xray не принял узел") {
		t.Fatalf("bad=%v", bad)
	}
	if !strings.Contains(bad[0], "unsupported transport") || strings.Contains(bad[0], "вторая строка") {
		t.Errorf("в сообщении должна быть только внятная часть: %q", bad[0])
	}
	var names []string
	for _, n := range good {
		names = append(names, n.Name)
	}
	if strings.Join(names, "") != "abcdefhijkl" {
		t.Errorf("порядок сбился: %v", names)
	}
	if runs >= len(nodes) {
		t.Errorf("делением пополам должно быть меньше %d запусков, вышло %d", len(nodes), runs)
	}

	// Все плохие — каждый назван поимённо.
	all := map[string]bool{}
	for _, n := range nodes {
		all[n.Name] = true
	}
	good, bad = bisectNodes(nodes, tester(all))
	if len(good) != 0 || len(bad) != 12 {
		t.Fatalf("good=%d bad=%d", len(good), len(bad))
	}

	if g, b := bisectNodes(nil, tester(nil)); g != nil || b != nil {
		t.Errorf("пустой набор: %v %v", g, b)
	}
}

// unixOnly пропускает тест, которому нужны /bin/sh или семантика файлов Unix
// (удаление открытого файла). В CI тесты идут на Linux и не пропускаются.
func unixOnly(t *testing.T) {
	t.Helper()
	if !unixPerms {
		t.Skip("только для Unix")
	}
}
