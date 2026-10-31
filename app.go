package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SubState struct {
	Name   string    `json:"name"`
	Nodes  int       `json:"nodes"`
	At     time.Time `json:"at"`
	Err    string    `json:"err"`
	Warns  []string  `json:"warns"`
	Info   *UserInfo `json:"info"`
	Cached bool      `json:"cached"` // узлы взяты из сохранённой копии
}

type App struct {
	c *Config
	w *Watcher
	n *Notifier

	mu        sync.Mutex
	subs      []Subscription
	states    map[string]*SubState // по URL
	nodes     []Node
	fbs       []Node // резервные узлы, принятые Xray
	geoAt     time.Time
	geoErr    string
	applyErr  string
	badNodes  []string
	listWarns []string
	written   [2][]byte // что xsub последний раз записал в 05_routing.json и 07_xsub.json
	xrayGone  int       // сколько проверок подряд ядро не запущено
	latest    string    // последняя версия на GitHub

	upgrading  atomic.Bool // идёт обновление пакета: второе нажатие кнопки не нужно
	refreshing atomic.Bool // идёт обновление подписок: страница следит за флагом в статусе

	// fetchMu — одно скачивание за раз (подписки, geo, внешние списки). Отдельно от opMu:
	// сеть с таймаутами в полторы минуты не должна держать сторож. Порядок захвата
	// всегда fetchMu → opMu, обратный порядок запрещён.
	fetchMu sync.Mutex

	kick chan struct{} // внеочередное обновление подписок
}

func newApp(c *Config) (*App, error) {
	subs, err := loadSubs(c)
	if err != nil {
		// Не стартуем из-за битого файла подписок — значит оставить роутер без
		// сторожа: текущий конфиг Xray продолжает работать, ошибка видна в журнале.
		lg.Printf("подписки не загружены (%v) — работаю без них, проверьте %s", err, subsFile)
	}
	a := &App{c: c, w: newWatcher(c), subs: subs, states: map[string]*SubState{}, kick: make(chan struct{}, 1)}
	a.n = newNotifier(c)
	a.w.notify = func(key, text string) {
		if strings.HasPrefix(key, "switch") && !c.Telegram.OnSwitch {
			return
		}
		a.n.send(key, text, 0)
	}
	return a, nil
}

func subKey(u string) string {
	h := sha1.Sum([]byte(u))
	return hex.EncodeToString(h[:])[:12]
}

func (a *App) cachePath(u string) string { return a.c.path(filepath.Join("cache", subKey(u)+".txt")) }

// fetchSub качает и разбирает подписку. HWID отправляется, только если без него
// узлов нет: иначе роутер зря занимал бы место в лимите устройств у панелей,
// которые пускают и без HWID. Тело парсится один раз — с тем флагом multi, с
// которым узлы пойдут в работу. hwid=true — панель выдала узлы только с HWID.
func (a *App) fetchSub(ctx context.Context, s Subscription, ua string, sock any, multi bool) ([]byte, http.Header, []Node, []string, bool, error) {
	b, h, err := fetchURLHeaders(ctx, a.c, s.URL, subHeaders(ua, ""), 8<<20)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	n, w := a.parseSub(s, b, sock, multi)
	if len(n) > 0 {
		return b, h, n, w, false, nil
	}
	if id := deviceHWID(a.c); id != "" {
		if b2, h2, err2 := fetchURLHeaders(ctx, a.c, s.URL, subHeaders(ua, id), 8<<20); err2 == nil {
			if n2, w2 := a.parseSub(s, b2, sock, multi); len(n2) > 0 {
				lg.Printf("подписка «%s»: панель выдаёт узлы только с HWID — отправлен HWID роутера", s.Name)
				return b2, h2, n2, w2, true, nil
			}
		}
	}
	return b, h, n, w, false, nil
}

func (a *App) parseSub(s Subscription, raw []byte, sockopt any, multi bool) ([]Node, []string) {
	o := parseOpts{sub: s.Name, sockopt: sockopt, maxNodes: a.c.MaxNodes}
	if s.Exclude != "" {
		o.exclude, _ = regexp.Compile(s.Exclude)
	}
	if s.Include != "" {
		o.include, _ = regexp.Compile(s.Include)
	}
	nodes, warns := parseSubscription(string(raw), o)
	if multi {
		for i := range nodes {
			nodes[i].Name = s.Name + " · " + nodes[i].Name
		}
	}
	return nodes, warns
}

func (a *App) sockopt() any {
	env, err := scanEnv(a.c)
	if err != nil {
		return nil
	}
	return env.Sockopt(a.c)
}

// xrayBootPolls — сколько секунд ждать запуска ядра после перезапуска.
// Переменная, чтобы тесты не ждали реальные двадцать секунд.
var xrayBootPolls = 20

// afterRestart: Xray перезапущен — ждём его и закрепляем узлы заново (или выбираем новые).
func (a *App) afterRestart(reason string) {
	for i := 0; i < xrayBootPolls && xrayStartTime(a.c) == ""; i++ {
		time.Sleep(time.Second)
	}
	time.Sleep(time.Duration(a.c.Watch.RestartDelaySec) * time.Second)
	a.w.repin(reason)
}

// apply — применить узлы и списки. Под opMu.
// Пока xsub ни разу не управлял Xray и узлов нет, конфиги не трогаем.
func (a *App) apply(nodes []Node, reason string, force bool) error {
	env, err := scanEnv(a.c)
	if err != nil {
		return err
	}
	fbs, fbWarns := fallbackNodes(a.c, env.Sockopt(a.c))
	if !force && len(nodes) == 0 && len(fbs) == 0 && !managed(a.c) {
		a.mu.Lock()
		a.nodes, a.fbs = nil, nil
		a.mu.Unlock()
		a.w.setNodes(nil, nil, nil)
		return nil
	}
	good, bad := validateNodes(a.c, append(append([]Node(nil), nodes...), fbs...))
	bad = append(fbWarns, bad...)
	for _, b := range bad {
		lg.Printf("%s", b)
	}
	a.mu.Lock()
	a.badNodes = bad
	a.mu.Unlock()
	nodes, fbs = nil, nil
	for _, n := range good {
		if isFallbackTag(n.Tag) {
			fbs = append(fbs, n)
		} else {
			nodes = append(nodes, n)
		}
	}
	changed, err := applyConfig(a.c, env, nodes, fbs, reason)
	a.mu.Lock()
	if err != nil {
		a.applyErr = err.Error()
	} else {
		a.applyErr = ""
		a.nodes, a.fbs = nodes, fbs
	}
	a.mu.Unlock()
	if err != nil {
		lg.Printf("конфиг не применён (%s): %v", reason, err)
		return err
	}
	a.rememberWritten()
	groups, _ := loadGroups(a.c)
	a.w.setNodes(nodes, fbs, targetDefs(a.c, nodes, groups))
	if rs, _, err := readRouting(a.c); err == nil {
		a.mu.Lock()
		a.listWarns = rs.Warnings
		a.mu.Unlock()
	}
	if changed && len(nodes) > 0 {
		a.afterRestart(reason)
	}
	a.w.selectMissing(reason)
	return nil
}

// rememberWritten запоминает содержимое файлов xsub, чтобы заметить, если их кто-то заменит.
func (a *App) rememberWritten() {
	r, _ := os.ReadFile(filepath.Join(a.c.Xray.ConfDir, routingFile))
	x, _ := os.ReadFile(filepath.Join(a.c.Xray.ConfDir, xsubFile))
	a.mu.Lock()
	a.written = [2][]byte{r, x}
	a.mu.Unlock()
}

// startup: geo-файлы, внешние списки, узлы из кэша, применение, выбор узлов.
func (a *App) startup() {
	a.updateGeo(context.Background(), false)
	nodes := a.collect(context.Background(), false) // только сохранённые копии, без сети
	a.mu.Lock()
	haveSubs := len(a.subs) > 0
	a.mu.Unlock()
	// Сохранённых копий нет, а подписки есть — их сейчас скачает subLoop; лишний перезапуск Xray не нужен.
	if len(nodes) > 0 || !haveSubs {
		opMu.Lock()
		defer opMu.Unlock()
		_ = a.apply(nodes, "запуск", false)
	}
}

// collect собирает узлы всех подписок: fetch=true — скачивает, иначе берёт сохранённые копии.
// Если подписка не скачалась, используется её сохранённая копия. Тело подписки
// парсится один раз: Clash YAML на мегабайты на mipsel — лишние секунды CPU.
func (a *App) collect(ctx context.Context, fetch bool) []Node {
	a.mu.Lock()
	subs := append([]Subscription(nil), a.subs...)
	a.mu.Unlock()
	sock := a.sockopt()
	multi := len(subs) > 1
	var all []Node
	seen := map[string]bool{}
	newStates := map[string]*SubState{}
	for _, s := range subs {
		a.mu.Lock()
		prev := a.states[s.URL]
		a.mu.Unlock()
		st := &SubState{Name: s.Name}
		if prev != nil {
			st.At, st.Info = prev.At, prev.Info
		}
		infoPath := strings.TrimSuffix(a.cachePath(s.URL), ".txt") + ".info"
		var nodes []Node
		var warns []string
		fresh := false
		if fetch {
			ua := firstNonEmpty(s.UserAgent, a.c.UserAgent)
			// := здесь был бы ловушкой: nodes/warns объявлены снаружи, а := внутри
			// блока создал бы теневые переменные — узлы потерялись бы по пути в apply.
			b, h, got, gw, _, err := a.fetchSub(ctx, s, ua, sock, multi)
			nodes, warns = got, gw
			if err != nil {
				st.Err = err.Error()
				lg.Printf("подписка «%s» не обновлена: %v", s.Name, err)
			} else {
				if len(nodes) == 0 {
					st.Err = "в ответе нет подходящих узлов (проверьте ссылку, фильтры и user_agent)"
					for _, x := range warns {
						if strings.HasPrefix(x, "пропущено информационных записей") {
							st.Err = fmt.Sprintf("панель прислала только служебные записи вместо узлов: проверьте user_agent; с HWID тоже не вышло — возможно, исчерпан лимит устройств (HWID роутера в файле %s)", a.c.path("hwid"))
							break
						}
					}
					st.Warns = warns
					lg.Printf("подписка «%s» не обновлена: %s", s.Name, st.Err)
					nodes = nil
				} else {
					fresh = true
					st.At = time.Now()
					st.Info = parseUserInfo(h)
					_ = os.MkdirAll(a.c.path("cache"), 0o700)
					writeIfChanged(a.cachePath(s.URL), b)
					if st.Info != nil {
						if ib, err := json.Marshal(st.Info); err == nil {
							writeIfChanged(infoPath, ib)
						}
					}
				}
			}
		}
		if !fresh && nodes == nil {
			if b, err := os.ReadFile(a.cachePath(s.URL)); err == nil {
				st.Cached = true
				if st.At.IsZero() {
					if fi, err := os.Stat(a.cachePath(s.URL)); err == nil {
						st.At = fi.ModTime()
					}
				}
				if st.Info == nil {
					if ib, err := os.ReadFile(infoPath); err == nil {
						var ui UserInfo
						if json.Unmarshal(ib, &ui) == nil {
							st.Info = &ui
						}
					}
				}
				nodes, warns = a.parseSub(s, b, sock, multi)
			}
		}
		st.Warns = append(st.Warns, warns...)
		for _, n := range nodes {
			if seen[n.Tag] {
				continue
			}
			seen[n.Tag] = true
			all = append(all, n)
			st.Nodes++
		}
		newStates[s.URL] = st
	}
	a.mu.Lock()
	a.states = newStates
	a.mu.Unlock()
	return all
}

// refreshSubs скачивает все подписки и применяет. Возвращает true, если какая-то не скачалась.
func (a *App) refreshSubs(ctx context.Context) (failed bool) {
	a.fetchMu.Lock()
	defer a.fetchMu.Unlock()
	a.refreshing.Store(true)
	defer a.refreshing.Store(false)
	nodes := a.collect(ctx, true) // сеть: до полутора минут на подписку, сторож в это время работает
	a.mu.Lock()
	for _, st := range a.states {
		if st.Err != "" {
			failed = true
		}
	}
	a.mu.Unlock()
	opMu.Lock()
	err := a.apply(nodes, "обновление подписок", false)
	opMu.Unlock()
	if err != nil {
		return true
	}
	a.checkSubLimits()
	return failed
}

// subLoop обновляет подписки по расписанию; после неудачи — повтор через 10 минут.
func (a *App) subLoop(ctx context.Context) {
	for {
		failed := true
		safely("обновлении подписок", func() { failed = a.refreshSubs(ctx) })
		d := time.Duration(a.c.SubIntervalHours) * time.Hour
		if failed {
			d = 10 * time.Minute
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-a.kick:
			t.Stop()
		}
	}
}

func (a *App) kickRefresh() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// checkSubLimits — уведомления о сроке действия и трафике подписок.
func (a *App) checkSubLimits() {
	tg := a.c.Telegram
	a.mu.Lock()
	type item struct {
		key, name string
		ui        UserInfo
	}
	var items []item
	for _, s := range a.subs {
		if st := a.states[s.URL]; st != nil && st.Info != nil {
			items = append(items, item{s.URL, s.Name, *st.Info})
		}
	}
	a.mu.Unlock()
	for _, it := range items {
		if it.ui.Expire > 0 && tg.ExpireDays > 0 {
			left := time.Until(time.Unix(it.ui.Expire, 0))
			if left < time.Duration(tg.ExpireDays)*24*time.Hour {
				msg := fmt.Sprintf("подписка «%s» заканчивается %s", it.name, time.Unix(it.ui.Expire, 0).Format("02.01.2006"))
				if left <= 0 {
					msg = fmt.Sprintf("подписка «%s» закончилась", it.name)
				}
				a.n.send("expire"+it.key, msg, 24*time.Hour)
			}
		}
		if it.ui.Total > 0 && tg.TrafficPct > 0 {
			used := it.ui.Upload + it.ui.Download
			if used*100 >= it.ui.Total*int64(tg.TrafficPct) {
				a.n.send("traffic"+it.key, fmt.Sprintf("подписка «%s»: израсходовано %.1f из %.1f ГБ",
					it.name, float64(used)/(1<<30), float64(it.ui.Total)/(1<<30)), 24*time.Hour)
			}
		}
	}
}

// saveSubs сохраняет список подписок с веб-страницы и запускает их обновление.
func (a *App) saveSubs(subs []Subscription) error {
	for i := range subs {
		subs[i].Name = strings.TrimSpace(subs[i].Name)
		subs[i].URL = strings.TrimSpace(subs[i].URL)
		subs[i].IntervalHours = 0
		if subs[i].Name == "" {
			subs[i].Name = fmt.Sprintf("Подписка %d", i+1)
		}
	}
	if err := validateSubs(subs); err != nil {
		return err
	}
	if err := saveSubsFile(a.c, subs); err != nil {
		return err
	}
	a.mu.Lock()
	a.subs = subs
	a.mu.Unlock()
	lg.Printf("список подписок сохранён: %d", len(subs))
	a.kickRefresh()
	return nil
}

// listFile — имя файла списка по его имени на странице: vpn, direct или id группы.
func (a *App) listFile(name string) (string, error) {
	switch name {
	case "vpn", "direct":
		return name + ".txt", nil
	}
	gs, _ := loadGroups(a.c)
	for _, g := range gs {
		if g.ID == name {
			return groupListName(g.ID), nil
		}
	}
	return "", fmt.Errorf("нет списка %s", name)
}

// saveList сохраняет список и применяет; при ошибке возвращает старый файл.
func (a *App) saveList(ctx context.Context, name, text string) error {
	file, err := a.listFile(name)
	if err != nil {
		return err
	}
	_, remotes, errs := parseListFull(text)
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	// Новые внешние списки скачиваем сразу, чтобы они попали в конфиг, — но до opMu.
	a.fetchMu.Lock()
	var rerrs []string
	for _, u := range remotes {
		if _, err := os.Stat(remotePath(a.c, u)); err != nil {
			if err := fetchRemote(ctx, a.c, u); err != nil {
				rerrs = append(rerrs, fmt.Sprintf("%s: %v", u, err))
			}
		}
	}
	a.fetchMu.Unlock()
	if len(rerrs) > 0 {
		return fmt.Errorf("не удалось скачать внешний список:\n%s", strings.Join(rerrs, "\n"))
	}
	opMu.Lock()
	defer opMu.Unlock()
	p := a.c.path(file)
	old, _ := os.ReadFile(p)
	if err := writeAtomicMode(p, []byte(text), 0o600); err != nil {
		return err
	}
	a.mu.Lock()
	nodes := a.nodes
	a.mu.Unlock()
	if err := a.apply(nodes, "изменён "+file, false); err != nil {
		_ = writeAtomicMode(p, old, 0o600)
		return err
	}
	lg.Printf("сохранён %s", file)
	return nil
}

// saveGroups сохраняет группы; списки удалённых групп удаляются.
func (a *App) saveGroups(gs []Group) error {
	for i := range gs {
		gs[i].Name = strings.TrimSpace(gs[i].Name)
		if gs[i].ID == "" {
			gs[i].ID = newGroupID(gs)
		}
	}
	if err := validateGroups(gs); err != nil {
		return err
	}
	opMu.Lock()
	defer opMu.Unlock()
	old, _ := loadGroups(a.c)
	b, _ := marshal(gs)
	if err := writeStateFile(a.c.path(groupsFile), b); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, g := range gs {
		keep[g.ID] = true
		if _, err := os.Stat(a.c.path(groupListName(g.ID))); err != nil {
			_ = os.WriteFile(a.c.path(groupListName(g.ID)), []byte("# Домены этой группы, формат как в vpn.txt\n"), 0o600)
		}
	}
	a.mu.Lock()
	nodes := a.nodes
	a.mu.Unlock()
	if err := a.apply(nodes, "изменены группы", false); err != nil {
		if ob, e := marshal(old); e == nil {
			_ = writeStateFile(a.c.path(groupsFile), ob)
		}
		return err
	}
	for _, g := range old {
		if !keep[g.ID] {
			_ = os.Remove(a.c.path(groupListName(g.ID)))
		}
	}
	lg.Printf("группы сохранены: %d", len(gs))
	return nil
}

func newGroupID(gs []Group) string {
	used := map[string]bool{}
	for _, g := range gs {
		used[g.ID] = true
	}
	for i := 1; ; i++ {
		id := fmt.Sprintf("g%d", i)
		if !used[id] {
			return id
		}
	}
}

func (a *App) updateGeo(ctx context.Context, force bool) {
	a.fetchMu.Lock()
	defer a.fetchMu.Unlock()
	a.updateGeoFiles(ctx, force)
	a.updateRemotes(ctx, force)
}

// updateRemotes обновляет внешние списки (force=false — только отсутствующие) и применяет,
// если что-то изменилось. Скачивание идёт без opMu, под ним только применение. Под fetchMu.
func (a *App) updateRemotes(ctx context.Context, force bool) {
	rs, _, err := readRouting(a.c)
	if err != nil {
		return
	}
	changed := false
	for _, u := range rs.Remotes {
		p := remotePath(a.c, u)
		old, oerr := os.ReadFile(p)
		if !force && oerr == nil {
			continue
		}
		if err := fetchRemote(ctx, a.c, u); err != nil {
			lg.Printf("внешний список %s не обновлён: %v", u, err)
			continue
		}
		if nb, _ := os.ReadFile(p); !bytes.Equal(old, nb) {
			changed = true
		}
	}
	if !changed || !managed(a.c) {
		return
	}
	a.mu.Lock()
	nodes := a.nodes
	a.mu.Unlock()
	opMu.Lock()
	defer opMu.Unlock()
	_ = a.apply(nodes, "обновлены внешние списки", false)
}

// updateGeoFiles: при force=false качает только отсутствующие файлы. Скачивание идёт
// без opMu, под ним только проверка конфига и перезапуск Xray. Под fetchMu.
func (a *App) updateGeoFiles(ctx context.Context, force bool) {
	var changed, errs []string
	for _, g := range a.c.Geo.Files {
		p := filepath.Join(a.c.Xray.AssetDir, g.Name)
		old, oerr := os.ReadFile(p)
		if !force && oerr == nil {
			continue
		}
		b, _, err := fetchURL(ctx, a.c, g.URL, "", 200<<20)
		if err == nil && len(b) < 1024 {
			err = fmt.Errorf("слишком маленький файл (%d байт)", len(b))
		}
		if err != nil {
			errs = append(errs, g.Name+": "+err.Error())
			continue
		}
		if bytes.Equal(old, b) {
			continue
		}
		if oerr == nil {
			_ = os.WriteFile(p+".bak", old, 0o644)
		}
		if err := writeAtomic(p, b); err != nil {
			errs = append(errs, g.Name+": "+err.Error())
			continue
		}
		changed = append(changed, p)
	}
	geoAtErrs := strings.Join(errs, "; ")
	a.mu.Lock()
	a.geoAt = time.Now()
	a.geoErr = geoAtErrs
	a.mu.Unlock()
	if len(errs) > 0 {
		lg.Printf("geo-файлы: %s", geoAtErrs)
	}
	if len(changed) == 0 {
		return
	}
	geoCache.reset() // файлы реально заменены — кэш категорий больше про них врёт
	if xrayStartTime(a.c) == "" {
		return
	}
	opMu.Lock()
	defer opMu.Unlock()
	if err := xrayTest(a.c, a.c.Xray.ConfDir); err != nil {
		lg.Printf("новые geo-файлы не прошли проверку, возвращаю старые: %v", err)
		for _, p := range changed {
			if b, e := os.ReadFile(p + ".bak"); e == nil {
				_ = writeAtomic(p, b)
			}
		}
		return
	}
	lg.Printf("geo-файлы обновлены: %d — перезапускаю Xray", len(changed))
	if err := restartXray(a.c); err != nil {
		lg.Printf("ошибка перезапуска: %v", err)
		return
	}
	if len(a.w.allTargets()) > 0 {
		a.afterRestart("после обновления geo")
	}
}

// healLoop — самовосстановление: файлы xsub подменили или ядро Xray пропало.
func (a *App) healLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		safely("самовосстановлении", a.heal)
	}
}

func (a *App) heal() {
	if !managed(a.c) {
		return
	}
	opMu.Lock()
	defer opMu.Unlock()
	// 1. Конфиги, которые записал xsub, заменили (обновление XKeen, ручная правка, другая панель).
	r, _ := os.ReadFile(filepath.Join(a.c.Xray.ConfDir, routingFile))
	x, _ := os.ReadFile(filepath.Join(a.c.Xray.ConfDir, xsubFile))
	a.mu.Lock()
	w := a.written
	nodes := a.nodes
	a.mu.Unlock()
	if w[0] != nil && (!bytes.Equal(r, w[0]) || !bytes.Equal(x, w[1])) {
		a.w.say("heal", "heal", "файлы конфигурации Xray изменены не xsub — восстанавливаю")
		_ = a.apply(nodes, "восстановление конфига", false)
		return
	}
	// 2. Ядро Xray не запущено (упало или XKeen остановился). Если запущен mihomo — это выбор пользователя.
	if !a.c.Watch.RestartXray || xrayStartTime(a.c) != "" {
		a.mu.Lock()
		a.xrayGone = 0
		a.mu.Unlock()
		return
	}
	if procStamp("mihomo") != "" {
		return
	}
	a.mu.Lock()
	a.xrayGone++
	gone := a.xrayGone
	a.mu.Unlock()
	if gone < 3 {
		return // ждём 3 минуты: XKeen мог перезапускаться
	}
	a.w.say("heal", "heal", "ядро Xray не запущено уже 3 минуты — перезапускаю XKeen")
	a.mu.Lock()
	a.xrayGone = 0
	a.mu.Unlock()
	if err := restartXray(a.c); err != nil {
		lg.Printf("перезапуск не удался: %v", err)
		return
	}
	a.afterRestart("после перезапуска Xray")
}

func every(ctx context.Context, what string, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safely(what, f)
		}
	}
}

type AppStatus struct {
	Status
	Version    string         `json:"version"`
	Latest     string         `json:"latest"`
	Refreshing bool           `json:"refreshing"` // идёт обновление подписок
	Server     bool           `json:"server"`     // серверный режим (Docker): обновление — новым образом
	Subs       []SubStatusOut `json:"subs"`
	Groups     []Group        `json:"groups"`
	GeoAt      time.Time      `json:"geo_at"`
	GeoErr     string         `json:"geo_err"`
	ApplyErr   string         `json:"apply_err"`
	BadNodes   []string       `json:"bad_nodes"`
	ListWarns  []string       `json:"list_warns"`
	Managed    bool           `json:"managed"`
	Events     []Event        `json:"events"`
	Log        []string       `json:"log"`
}

type SubStatusOut struct {
	Subscription
	State *SubState `json:"state"`
}

func (a *App) status() AppStatus {
	s := AppStatus{Status: a.w.status(), Version: version, Managed: managed(a.c), Refreshing: a.refreshing.Load(), Server: serverMode}
	s.Groups, _ = loadGroups(a.c)
	a.mu.Lock()
	for _, sub := range a.subs {
		s.Subs = append(s.Subs, SubStatusOut{Subscription: sub, State: a.states[sub.URL]})
	}
	s.GeoAt, s.GeoErr, s.ApplyErr = a.geoAt, a.geoErr, a.applyErr
	s.BadNodes, s.ListWarns, s.Latest = a.badNodes, a.listWarns, a.latest
	a.mu.Unlock()
	s.Events = events.list()
	s.Log = lg.Tail(80)
	return s
}

// writeIfChanged не трогает файл, если содержимое не изменилось (бережём флеш-память).
func writeIfChanged(path string, b []byte) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return
	}
	_ = writeAtomicMode(path, b, 0o600)
}
