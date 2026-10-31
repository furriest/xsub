package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeProbe — пробы сторожа без сети и без Xray: результат задаётся по портам.
// Порты не из карт дают ошибку — тест обязан явно настроить каждую проверку.
type fakeProbe struct {
	load   map[int]error // порт входа → ошибка загрузки (nil — проходит)
	lat    map[int]int   // порт → задержка (меньше 0 — не измерена)
	online bool
	bo     map[string]string // balancer → закреплённый тег (nil — override ошибкой)
}

func (f *fakeProbe) realTest(port int) error {
	if err, ok := f.load[port]; ok {
		return err
	}
	return fmt.Errorf("fake: загрузка с порта %d не настроена", port)
}

func (f *fakeProbe) latency(port int) (int, error) {
	if ms, ok := f.lat[port]; ok {
		if ms < 0 {
			return -1, errors.New("timeout")
		}
		return ms, nil
	}
	return -1, errors.New("не настроено")
}

func (f *fakeProbe) internetOK() bool { return f.online }

func (f *fakeProbe) override(balancer, tag string) error {
	if f.bo == nil {
		return errors.New("override не настроен")
	}
	f.bo[balancer] = tag
	return nil
}

// newTestWatcher собирает сторож на фейковых пробах: узлам порты выдаются
// с TestPortBase по порядку (как в setNodesLocked), резервам — за ними.
func newTestWatcher(f *fakeProbe, nodes, fbs []Node) *Watcher {
	c := defaultConfig()
	c.Watch.StatsFile = "" // не подхватывать историю с машины разработчика
	w := newWatcher(c)
	w.pr = f
	w.setNodes(nodes, fbs, []TargetDef{
		{Name: "основной", Balancer: c.Xray.Balancer, ProbePort: c.Xray.ProbePort},
	})
	return w
}

func mkNode(tag, name string) Node { return Node{Tag: tag, Name: name} }

func activeTag(w *Watcher) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.target("").Active
}

func TestSelectNodePrefersLowerLatency(t *testing.T) {
	f := &fakeProbe{
		lat: map[int]int{11000: 50, 11001: 10},
		load: map[int]error{
			11000: nil, 11001: nil,
			10990: nil, // probe-вход основной цели
		},
		online: true, bo: map[string]string{},
	}
	w := newTestWatcher(f, []Node{mkNode("node-a", "A"), mkNode("node-b", "B")}, nil)
	w.selectNode(w.target(""), "тест")
	if got := activeTag(w); got != "node-b" {
		t.Fatalf("выбран %s, ожидался node-b (задержка меньше)", got)
	}
}

// Регрессия: узел, чья задержка не измерилась (latency_url через него не открылся),
// раньше выпадал из автовыбора навсегда — хотя рабочесть решает проверка загрузкой.
func TestSelectNodeTakesNodeWithUnknownLatency(t *testing.T) {
	f := &fakeProbe{
		lat: map[int]int{11000: -1, 11001: 30},
		load: map[int]error{
			11000: nil, // загрузка через «немого» узла проходит
			11001: errors.New("обрыв"),
			10990: nil,
		},
		online: true, bo: map[string]string{},
	}
	w := newTestWatcher(f, []Node{mkNode("node-a", "A"), mkNode("node-b", "B")}, nil)
	w.selectNode(w.target(""), "тест")
	if got := activeTag(w); got != "node-a" {
		t.Fatalf("выбран %s, ожидался node-a (загрузка проходит, задержка не важна)", got)
	}
	if n := w.node("node-a"); n.LatencyMs != -1 {
		t.Fatalf("задержка должна остаться -1, а не %d", n.LatencyMs)
	}
}

func TestCheckTargetSwitchesAfterFailsToSwitch(t *testing.T) {
	oldDelay := retestDelay
	retestDelay = 0
	t.Cleanup(func() { retestDelay = oldDelay })

	f := &fakeProbe{
		lat: map[int]int{11000: 10, 11001: 20},
		load: map[int]error{
			10990: errors.New("залип"), // активный узел не качает
			11000: errors.New("залип"),
			11001: nil,
		},
		online: true, bo: map[string]string{},
	}
	w := newTestWatcher(f, []Node{mkNode("node-a", "A"), mkNode("node-b", "B")}, nil)
	tgt := w.target("")
	w.mu.Lock()
	tgt.Active = "node-a"
	tgt.lastSelect = time.Now()
	w.mu.Unlock()

	w.checkTarget(tgt)
	if got := activeTag(w); got != "node-a" {
		t.Fatalf("после первой неудачи переключились на %s", got)
	}
	w.checkTarget(tgt)
	if got := activeTag(w); got != "node-b" {
		t.Fatalf("после второй неудачи выбран %s, ожидался node-b", got)
	}
	n := w.node("node-a")
	if !time.Now().Before(n.BadUntil) {
		t.Error("залипшему узлу не выставлен BadUntil")
	}
	if !strings.HasPrefix(n.LastErr, "залип") {
		t.Errorf("LastErr залипшего: %q", n.LastErr)
	}
}

func TestFallbackEngagedAndReturned(t *testing.T) {
	f := &fakeProbe{
		lat: map[int]int{11000: 10, 11001: 20},
		load: map[int]error{
			11000: errors.New("лежит"),
			11001: nil, // резервный узел работает
			10990: nil,
		},
		online: true, bo: map[string]string{},
	}
	fb := mkNode("fb-test1", "Резерв")
	w := newTestWatcher(f, []Node{mkNode("node-a", "A")}, []Node{fb})
	w.selectNode(w.target(""), "тест")
	if got := activeTag(w); got != "fb-test1" {
		t.Fatalf("без рабочих узлов выбран %s, ожидался резерв", got)
	}
	// Резерв работает: трафик пошёл через него.
	if f.bo["xsub"] != "fb-test1" {
		t.Fatalf("балансировщик закреплён за %q", f.bo["xsub"])
	}
	// Узлы подписки ожили — возвращаемся с резерва.
	f.load[11000] = nil
	w.selectNode(w.target(""), "возврат")
	if got := activeTag(w); got != "node-a" {
		t.Fatalf("после восстановления выбран %s, ожидался node-a", got)
	}
}

func TestSwitchFasterMovesToQuickerNode(t *testing.T) {
	f := &fakeProbe{
		lat: map[int]int{11000: 100, 11001: 50},
		load: map[int]error{
			11000: nil, 11001: nil, // кандидат дважды проверяется прямо сейчас
			10990: nil,
		},
		online: true, bo: map[string]string{},
	}
	c := defaultConfig()
	c.Watch.SwitchFasterMs = 40
	c.Watch.StatsFile = ""
	w := newWatcher(c)
	w.pr = f
	w.setNodes([]Node{mkNode("node-a", "A"), mkNode("node-b", "B")}, nil,
		[]TargetDef{{Name: "основной", Balancer: c.Xray.Balancer, ProbePort: c.Xray.ProbePort}})
	tgt := w.target("")
	w.mu.Lock()
	tgt.Active = "node-a"
	tgt.lastSelect = time.Now().Add(-time.Hour) // cooldown на смену узла прошёл
	w.mu.Unlock()
	w.checkAll() // задержки узлов — как после фоновых проверок

	w.switchFaster()
	if got := activeTag(w); got != "node-b" {
		t.Fatalf("переключились на %s, ожидался более быстрый node-b", got)
	}
	if f.bo["xsub"] != "node-b" {
		t.Fatalf("балансировщик закреплён за %q", f.bo["xsub"])
	}
}

func TestPickDueDistributesChecks(t *testing.T) {
	now := time.Now()
	nodes := []*NodeState{
		{Node: mkNode("node-a", "A"), Stats: &NodeStats{LastTest: now.Add(-40 * time.Minute)}},
		{Node: mkNode("node-b", "B"), Stats: &NodeStats{LastTest: now.Add(-10 * time.Minute)}},
		{Node: mkNode("node-c", "C"), Stats: &NodeStats{LastTest: now.Add(-35 * time.Minute)}},
	}
	due := pickDue(nodes, map[string]bool{"node-b": true}, now, 30*time.Minute, time.Minute)
	if len(due) != 1 || due[0].Tag != "node-a" {
		t.Fatalf("due: %v, ожидался только самый просроченный неактивный узел", due)
	}
	// Активный узель больше не проверяем, чем нужно для цикла: при 2 запасных и
	// тике в минуту за тик положена одна проверка.
	nodes[1].Stats.LastTest = now.Add(-40 * time.Minute)
	due = pickDue(nodes, nil, now, 30*time.Minute, time.Minute)
	if len(due) != 1 {
		t.Fatalf("квота на тик: %v", due)
	}
}
