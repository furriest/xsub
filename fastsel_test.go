package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// countProbe — fakeProbe со счётчиком вызовов: проверки выбора узла теперь
// идут параллельно, поэтому счёт под замком.
type countProbe struct {
	*fakeProbe
	mu    sync.Mutex
	loads map[int]int
	lats  map[int]int
}

func newCountProbe(f *fakeProbe) *countProbe {
	return &countProbe{fakeProbe: f, loads: map[int]int{}, lats: map[int]int{}}
}

func (c *countProbe) realTest(port int) error {
	c.mu.Lock()
	c.loads[port]++
	c.mu.Unlock()
	return c.fakeProbe.realTest(port)
}

func (c *countProbe) latency(port int) (int, error) {
	c.mu.Lock()
	c.lats[port]++
	c.mu.Unlock()
	return c.fakeProbe.latency(port)
}

func (c *countProbe) total(m map[int]int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// deadNodes — n узлов, из которых живы только перечисленные индексы.
func deadNodes(n int, alive ...int) ([]Node, *fakeProbe) {
	f := &fakeProbe{lat: map[int]int{}, load: map[int]error{}, online: true, bo: map[string]string{}}
	live := map[int]bool{}
	for _, i := range alive {
		live[i] = true
	}
	var nodes []Node
	for i := 0; i < n; i++ {
		nodes = append(nodes, mkNode(fmt.Sprintf("n%d", i), fmt.Sprintf("N%d", i)))
		port := 11000 + i
		if live[i] {
			f.lat[port], f.load[port] = 40+i, nil
		} else {
			f.lat[port], f.load[port] = -1, errors.New("timeout")
		}
	}
	return nodes, f
}

func TestTryOrderLiveFirstMuteLimited(t *testing.T) {
	var cands []*NodeState
	for i, ms := range []int{-1, 30, -1, -1, 0, 20, -1} {
		cands = append(cands, &NodeState{Node: mkNode(fmt.Sprintf("t%d", i), ""), LatencyMs: ms})
	}
	got := tryOrder(cands, 20)
	var tags []string
	for _, n := range got {
		tags = append(tags, n.Tag)
	}
	want := "[t1 t5 t0 t2 t3]" // живые в прежнем порядке, затем muteTries «немых»
	if fmt.Sprint(tags) != want {
		t.Fatalf("порядок %v, ожидался %s", tags, want)
	}
	if got := tryOrder(cands, 2); len(got) != 2 || got[0].Tag != "t1" {
		t.Fatalf("max_try не соблюдён: %d узлов", len(got))
	}
}

// Главный сценарий проблемы: большинство узлов мёртвые. Загрузкой проверяется
// не больше живых + окно + muteTries, а не все max_try.
func TestSelectNodeSkipsMostDeadNodes(t *testing.T) {
	nodes, f := deadNodes(30, 25)
	cp := newCountProbe(f)
	w := newTestWatcher(f, nodes, nil)
	w.pr = cp
	w.selectNode(w.target(""), "тест")
	if got := activeTag(w); got != "n25" {
		t.Fatalf("выбран %q, ожидался единственный живой n25", got)
	}
	if n := cp.total(cp.loads); n > selectParallel {
		t.Fatalf("загрузкой проверено %d узлов — живой узел первым, лишних не больше окна", n)
	}
}

func TestSelectNodeAllDeadTriesOnlyFewMute(t *testing.T) {
	nodes, f := deadNodes(30)
	cp := newCountProbe(f)
	w := newTestWatcher(f, nodes, nil)
	w.pr = cp
	w.selectNode(w.target(""), "тест")
	if got := activeTag(w); got != "" {
		t.Fatalf("выбран %q, хотя живых нет", got)
	}
	if n := cp.total(cp.loads); n != muteTries {
		t.Fatalf("загрузкой проверено %d узлов, ожидалось muteTries=%d", n, muteTries)
	}
}

// Замер перед выбором — только узлы цели и только с устаревшим замером.
func TestMeasureStaleOnlyTargetAndStale(t *testing.T) {
	nodes, f := deadNodes(4, 0, 1, 2, 3)
	cp := newCountProbe(f)
	w := newTestWatcher(f, nodes, nil)
	w.pr = cp
	tgt := &Target{tags: map[string]bool{"n0": true, "n1": true, "n2": true}}
	w.mu.Lock()
	w.find("n1").CheckedAt = time.Now()                    // свежий
	w.find("n2").CheckedAt = time.Now().Add(-latencyFresh) // устарел
	w.mu.Unlock()
	w.measureStale(tgt)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.lats[11000] != 1 || cp.lats[11001] != 0 || cp.lats[11002] != 1 || cp.lats[11003] != 0 {
		t.Fatalf("замеры по портам: %v (ожидались n0 и n2)", cp.lats)
	}
}

// После таймаута запасной адрес замера не запрашивается; после отказа — да.
func TestIsTimeout(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer hang.Close()
	cl := &http.Client{Timeout: 50 * time.Millisecond}
	_, err := cl.Get(hang.URL)
	if err == nil || !isTimeout(err) {
		t.Fatalf("таймаут клиента не распознан: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if _, err := cl.Get("http://" + addr); err == nil || isTimeout(err) {
		t.Fatalf("отказ соединения принят за таймаут: %v", err)
	}
}

func TestLatencyTimeoutDefaults(t *testing.T) {
	c := defaultConfig()
	if c.Watch.LatencyTimeoutSec >= c.Watch.TimeoutSec {
		t.Fatalf("замер задержки (%d с) должен быть короче проверки загрузкой (%d с)", c.Watch.LatencyTimeoutSec, c.Watch.TimeoutSec)
	}
}

// apply не ждёт подбор узлов: он идёт в фоне, повторные запросы сливаются.
func TestSettleRunsInBackground(t *testing.T) {
	nodes, f := deadNodes(3, 1)
	cp := newCountProbe(f)
	w := newTestWatcher(f, nodes, nil)
	w.pr = cp
	a := &App{c: w.c, w: w}

	opMu.Lock() // как в apply: планирование идёт под opMu
	a.scheduleSettle("первое", false, "")
	a.scheduleSettle("второе", false, "")
	if !w.settling.Load() {
		opMu.Unlock()
		t.Fatal("флаг settling не поднят")
	}
	if got := activeTag(w); got != "" {
		opMu.Unlock()
		t.Fatalf("узел выбран синхронно: %q", got)
	}
	opMu.Unlock()

	done := make(chan struct{})
	go func() { a.waitSettle(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("фоновый подбор не завершился")
	}
	if w.settling.Load() {
		t.Fatal("флаг settling не снят")
	}
	if got := activeTag(w); got != "n1" {
		t.Fatalf("фоновый подбор выбрал %q, ожидался n1", got)
	}
	// Два запроса слились в один выбор: живой n1 проверен загрузкой один раз.
	cp.mu.Lock()
	n1 := cp.loads[11001]
	cp.mu.Unlock()
	if n := n1; n != 1 {
		t.Fatalf("n1 проверен %d раз — запросы не слились", n)
	}
}
