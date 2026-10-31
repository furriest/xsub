// Состояние сторожа: узлы, цели и доступ к ним.
//
// Дисциплина блокировок, три замка и всегда в этом порядке:
//
//	App.fetchMu — одно скачивание за раз (подписки, geo, внешние списки);
//	opMu        — одна тяжёлая операция с Xray за раз: генерация конфига,
//	              xray -test, перезапуск ядра, выбор узла;
//	Watcher.mu  — поля Watcher и всё, на что он ссылается: nodes, fbs, targets,
//	              stats, изменяемые поля NodeState (LatencyMs, CheckedAt, BadUntil,
//	              LastErr, Stats) и Target (Active, Pinned, Fails, Down, Slots).
//
// Config после загрузки не меняется и читается без замка. Неизменяемые поля
// NodeState (Node, TestPort, Fallback) и Target (TargetDef, tags) заполняются в
// setNodes до публикации и дальше только читаются. Сетевые пробы и запуск
// процессов выполняются вне Watcher.mu: он не должен ждать сеть.
package main

import (
	"fmt"
	"sync"
	"time"
)

type NodeState struct {
	Node
	TestPort  int        `json:"test_port"`
	LatencyMs int        `json:"latency_ms"` // 0 — не проверялся, -1 — недоступен
	CheckedAt time.Time  `json:"checked_at"`
	BadUntil  time.Time  `json:"bad_until"`
	LastErr   string     `json:"last_err"`
	Stats     *NodeStats `json:"stats"`
	Fallback  bool       `json:"fallback,omitempty"` // резервный узел xsub
}

// Target — то, за чем следит сторож: основной балансировщик или балансировщик группы.
type Target struct {
	TargetDef
	tags       map[string]bool
	Active     string
	Pinned     bool
	Fails      int
	LastOK     time.Time
	Down       bool
	lastSelect time.Time
	Slots      []Slot // доступность цели по получасам
}

func (t *Target) has(tag string) bool { return t.tags == nil || t.tags[tag] }

// allows — узел можно назначить цели: её собственный или резервный (резервы общие для всех).
func (t *Target) allows(tag string) bool { return isFallbackTag(tag) || t.has(tag) }

func (t *Target) where() string {
	if t.ID == "" {
		return ""
	}
	return " [" + t.Name + "]"
}

type Watcher struct {
	c *Config

	mu        sync.Mutex
	nodes     []*NodeState
	fbs       []*NodeState // резервные узлы: включаются, когда не работает ни один узел подписок
	targets   []*Target
	stats     map[string]*NodeStats // переживает обновление подписки
	seeded    bool                  // список узлов уже заполнялся хотя бы раз
	noNet     bool                  // не отвечает ни один direct_urls — проверки приостановлены
	xrayStart string

	pr     prober                 // пробы: настоящее ядро Xray или фейк в тестах
	notify func(key, text string) // уведомления (Telegram); может быть nil
}

func newWatcher(c *Config) *Watcher {
	w := &Watcher{c: c, stats: map[string]*NodeStats{}, pr: xrayProbe{c: c}}
	w.loadStats()
	return w
}

// say пишет в журнал, в историю и (если key не пустой) отправляет уведомление.
func (w *Watcher) say(key, kind, text string) {
	lg.Printf("%s", text)
	events.add(kind, text)
	if w.notify != nil && key != "" {
		w.notify(key, text)
	}
}

// setNodes обновляет узлы, резервы и цели, сохраняя накопленное состояние.
func (w *Watcher) setNodes(nodes, fbs []Node, defs []TargetDef) {
	for _, m := range w.setNodesLocked(nodes, fbs, defs) {
		w.say("", "info", m)
	}
}

// setNodesLocked — сама подмена списков; возвращает сообщения об узлах, которых
// раньше не было. Тестовые порты: узлы с test_port_base, за ними резервы (как в generate).
func (w *Watcher) setNodesLocked(nodes, fbs []Node, defs []TargetDef) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	var fresh []string
	old := map[string]*NodeState{}
	for _, n := range append(append([]*NodeState(nil), w.nodes...), w.fbs...) {
		old[n.Tag] = n
	}
	all := append(append([]Node(nil), nodes...), fbs...)
	var ns, fs []*NodeState
	for i, n := range all {
		st := &NodeState{Node: n, Fallback: i >= len(nodes)}
		if o, ok := old[n.Tag]; ok {
			st.LatencyMs, st.CheckedAt, st.BadUntil, st.LastErr = o.LatencyMs, o.CheckedAt, o.BadUntil, o.LastErr
		}
		if w.stats[n.Tag] == nil {
			w.stats[n.Tag] = newStats()
			if w.seeded {
				// Тег считается по адресу, порту, SNI и транспорту: панель перенесла узел
				// на другой хост — для сторожа это новый узел с пустой историей.
				fresh = append(fresh, fmt.Sprintf("новый узел «%s» (%s) — история проверок начата заново", n.Name, nodeSummary(n)))
			}
		}
		w.stats[n.Tag].Seen = now
		st.Stats = w.stats[n.Tag]
		st.TestPort = w.c.Xray.TestPortBase + i
		if st.Fallback {
			fs = append(fs, st)
		} else {
			ns = append(ns, st)
		}
	}
	w.nodes, w.fbs = ns, fs

	oldT := map[string]*Target{}
	for _, t := range w.targets {
		oldT[t.ID] = t
	}
	var ts []*Target
	for _, d := range defs {
		if len(ns) == 0 || (d.ID != "" && d.Empty) {
			continue // у группы нет узлов — её трафик идёт основной целью
		}
		t := &Target{TargetDef: d}
		if d.Tags != nil {
			t.tags = map[string]bool{}
			for _, tag := range d.Tags {
				t.tags[tag] = true
			}
		}
		if o, ok := oldT[d.ID]; ok {
			t.Active, t.Pinned, t.Fails, t.LastOK, t.Down, t.lastSelect, t.Slots = o.Active, o.Pinned, o.Fails, o.LastOK, o.Down, o.lastSelect, o.Slots
		}
		if t.Active != "" && (!t.allows(t.Active) || w.find(t.Active) == nil) {
			t.Active, t.Pinned = "", false
		}
		ts = append(ts, t)
	}
	w.targets = ts
	if len(all) > 0 {
		w.seeded = true
	}
	w.dropOrphans(now)
	return fresh
}

// dropOrphans выбрасывает статистику узлов, которых нет в списке уже сутки:
// их получасовая история к этому моменту всё равно пуста, а карта иначе растёт
// без конца — панели меняют адреса узлов, и каждый перенос добавляет в неё тег. Под w.mu.
func (w *Watcher) dropOrphans(now time.Time) {
	for tag, s := range w.stats {
		if now.Sub(s.Seen) > slotDur*slotCount {
			delete(w.stats, tag)
		}
	}
}

func (w *Watcher) find(tag string) *NodeState {
	for _, n := range w.nodes {
		if n.Tag == tag {
			return n
		}
	}
	for _, n := range w.fbs {
		if n.Tag == tag {
			return n
		}
	}
	return nil
}

func (w *Watcher) node(tag string) *NodeState {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.find(tag)
}

func (w *Watcher) target(id string) *Target {
	for _, t := range w.targets {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (w *Watcher) nodeName(tag string) string {
	if n := w.find(tag); n != nil {
		return n.Name
	}
	return tag
}

func (w *Watcher) record(tag string, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s := w.stats[tag]; s != nil {
		s.record(ok, time.Now())
	}
}

func (w *Watcher) allTargets() []*Target {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*Target(nil), w.targets...)
}

type TargetStatus struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Active     string    `json:"active"`
	ActiveName string    `json:"active_name"`
	Pinned     bool      `json:"pinned"`
	Down       bool      `json:"down"`
	LastOK     time.Time `json:"last_ok"`
	Tags       []string  `json:"tags"`
	Slots      []Slot    `json:"slots"`
}

type Status struct {
	Targets   []TargetStatus `json:"targets"`
	XrayUp    bool           `json:"xray_up"`
	Nodes     []*NodeState   `json:"nodes"`
	Fallbacks []*NodeState   `json:"fallbacks"`
}

func (w *Watcher) status() Status {
	up := xrayStartTime(w.c) != "" // обход /proc — не под мьютексом сторожа
	w.mu.Lock()
	defer w.mu.Unlock()
	s := Status{XrayUp: up}
	for _, t := range w.targets {
		s.Targets = append(s.Targets, TargetStatus{
			ID: t.ID, Name: t.Name, Active: t.Active, ActiveName: w.nodeName(t.Active), Pinned: t.Pinned,
			Down: t.Down, LastOK: t.LastOK, Tags: t.Tags, Slots: append([]Slot(nil), t.Slots...),
		})
	}
	copyNode := func(n *NodeState) *NodeState {
		cp := *n
		if n.Stats != nil {
			sc := *n.Stats
			sc.Slots = append([]Slot(nil), n.Stats.Slots...)
			cp.Stats = &sc
		}
		return &cp
	}
	for _, n := range w.nodes {
		s.Nodes = append(s.Nodes, copyNode(n))
	}
	for _, n := range w.fbs {
		s.Fallbacks = append(s.Fallbacks, copyNode(n))
	}
	return s
}
