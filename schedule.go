// Расписание сторожа: тик, проверка целей и обход запасных узлов в фоне.

package main

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

func (w *Watcher) loop(ctx context.Context) {
	t := time.NewTicker(time.Duration(w.c.Watch.IntervalSec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if w.c.Watch.Enabled {
			safely("проверке узлов", w.tick)
		}
	}
}

func (w *Watcher) tick() {
	opMu.Lock()
	defer opMu.Unlock()
	st := xrayStartTime(w.c)
	if st == "" {
		return // ядро не запущено — этим занимается самовосстановление
	}
	w.mu.Lock()
	restarted := st != w.xrayStart
	w.mu.Unlock()
	targets := w.allTargets()
	if len(targets) == 0 {
		return
	}
	if restarted {
		time.Sleep(time.Duration(w.c.Watch.RestartDelaySec) * time.Second)
		lg.Printf("Xray перезапущен — закрепляю выбранные узлы снова")
		w.repin("после перезапуска Xray")
	}
	for _, t := range targets {
		w.checkTarget(t)
	}
	w.background()
	w.switchFaster()
}

const fallbackRetry = 10 * time.Minute

// retestDelay — пауза между повторной проверкой после восстановления закрепления.
// Переменная, чтобы тесты не ждали реальные две секунды.
var retestDelay = 2 * time.Second

func (w *Watcher) checkTarget(t *Target) {
	w.mu.Lock()
	active, pinned, since := t.Active, t.Pinned, time.Since(t.lastSelect)
	w.mu.Unlock()
	if active == "" {
		if since > 5*time.Minute {
			w.selectNode(t, "поиск рабочего узла")
		}
		return
	}
	// На резерве (не выбранном вручную) — раз в 10 минут пробуем вернуться на узлы подписки.
	if isFallbackTag(active) && !pinned && since > fallbackRetry {
		w.selectNode(t, "возврат с резерва")
		return
	}
	err := w.realTest(t.ProbePort)
	if err != nil {
		if !w.internetOK() {
			// Интернета нет вообще — VPN не виноват, и проверка не записывается.
			// Иначе в полосе за сутки появляется необъяснимая дырка.
			if w.setNoNet(true) {
				w.say("", "down", "нет связи с интернетом: не отвечает ни один адрес из direct_urls — проверки узлов приостановлены")
			}
			return
		}
		// Закрепление могло пропасть (Xray перезапускался) — восстанавливаем и проверяем ещё раз.
		if w.override(t.Balancer, active) == nil {
			time.Sleep(retestDelay)
			if w.realTest(t.ProbePort) == nil {
				err = nil
			}
		}
	}
	if w.setNoNet(false) {
		w.say("", "up", "связь с интернетом вернулась — проверки узлов возобновлены")
	}
	w.record(active, err == nil)
	if err == nil {
		if n := w.node(active); n != nil {
			w.measure(n)
		}
	}
	w.mu.Lock()
	addSlot(&t.Slots, err == nil, time.Now())
	if err == nil {
		t.Fails, t.LastOK = 0, time.Now()
		w.mu.Unlock()
		return
	}
	t.Fails++
	fails := t.Fails
	name := w.nodeName(active)
	w.mu.Unlock()
	lg.Printf("проверка не прошла (%d/%d), узел «%s»%s: %s", fails, w.c.Watch.FailsToSwitch, name, t.where(), shortErr(err))
	if fails < w.c.Watch.FailsToSwitch {
		return
	}
	w.mu.Lock()
	if n := w.find(active); n != nil {
		n.BadUntil = time.Now().Add(time.Duration(w.c.Watch.BadCooldownMin) * time.Minute)
		n.LastErr = "залип: " + shortErr(err)
	}
	t.Fails = 0
	w.mu.Unlock()
	if pinned {
		lg.Printf("вручную выбранный узел «%s» залип — снимаю ручной выбор", name)
	}
	w.selectNode(t, fmt.Sprintf("узел «%s» залип", name))
}

// background проверяет загрузкой запасные узлы так, чтобы каждый проверялся
// раз в background_cycle_min минут; проверки распределяются по тикам равномерно,
// первыми идут те, кого не проверяли дольше всех.
func (w *Watcher) background() {
	cycle := time.Duration(w.c.Watch.BackgroundCycleMin) * time.Minute
	if cycle <= 0 {
		return
	}
	tick := time.Duration(w.c.Watch.IntervalSec) * time.Second
	w.mu.Lock()
	active := map[string]bool{}
	for _, t := range w.targets {
		if t.Active != "" { // у цели может не быть узла — пустой ключ в карте ни к чему
			active[t.Active] = true
		}
	}
	due := pickDue(append(append([]*NodeState(nil), w.nodes...), w.fbs...), active, time.Now(), cycle, tick)
	w.mu.Unlock()
	for _, n := range due {
		err := w.realTest(n.TestPort)
		w.record(n.Tag, err == nil)
		if err == nil {
			w.measure(n)
		}
		w.mu.Lock()
		if err != nil {
			n.LatencyMs, n.CheckedAt = -1, time.Now()
			n.LastErr = "фоновая проверка: " + shortErr(err)
		} else if strings.HasPrefix(n.LastErr, "фоновая проверка") || strings.HasPrefix(n.LastErr, "загрузка") {
			n.LastErr = ""
		}
		w.mu.Unlock()
	}
}

// pickDue выбирает запасные узлы для фоновой проверки в этом тике: тех, кого не проверяли
// дольше cycle, самых «старых» первыми, не больше чем нужно, чтобы обойти всех за cycle.
func pickDue(nodes []*NodeState, active map[string]bool, now time.Time, cycle, tick time.Duration) []*NodeState {
	var spare, due []*NodeState
	for _, n := range nodes {
		if active[n.Tag] {
			continue
		}
		spare = append(spare, n)
		if n.Stats == nil || now.Sub(n.Stats.LastTest) >= cycle-tick/2 {
			due = append(due, n)
		}
	}
	last := func(n *NodeState) time.Time {
		if n.Stats == nil {
			return time.Time{}
		}
		return n.Stats.LastTest
	}
	sort.SliceStable(due, func(i, j int) bool { return last(due[i]).Before(last(due[j])) })
	quota := bgQuota(len(spare), tick, cycle)
	if quota > len(due) {
		quota = len(due)
	}
	return due[:quota]
}

// bgQuota — сколько узлов проверять за тик, чтобы обойти n узлов за cycle (не меньше одного).
// Считается в float: в наносекундах int переполняется на 32-битных роутерах.
func bgQuota(n int, tick, cycle time.Duration) int {
	if n == 0 || cycle <= 0 {
		return 0
	}
	q := int(math.Ceil(float64(n) * tick.Seconds() / cycle.Seconds()))
	if q < 1 {
		q = 1
	}
	return q
}
