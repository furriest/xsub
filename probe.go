// Пробы: проверка узла загрузкой, замер задержки, состояние ядра Xray.

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// prober — то, чем сторож проверяет узлы и управляет ими: загрузка через локальный
// вход Xray, замер задержки, доступность интернета, закрепление балансировщика
// через API. За интерфейсом прячется настоящее ядро — в тестах его подменяет
// фейк, и выбор узла гоняется без сети и без Xray.
type prober interface {
	realTest(port int) error
	latency(port int) (int, error)
	internetOK() bool
	override(balancer, tag string) error
	probeReady(secs int)
}

// xrayProbe — пробы через настоящее ядро Xray.
type xrayProbe struct{ c *Config }

func (w *Watcher) realTest(port int) error       { return w.pr.realTest(port) }
func (w *Watcher) latency(port int) (int, error) { return w.pr.latency(port) }
func (w *Watcher) internetOK() bool              { return w.pr.internetOK() }
func (w *Watcher) probeReady(secs int)           { w.pr.probeReady(secs) }

func socksClient(port int, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)}),
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// realTest — реальная загрузка через локальный вход Xray плюс открытие адресов из check_urls.
func (x xrayProbe) realTest(port int) error {
	cl := socksClient(port, time.Duration(x.c.Watch.TimeoutSec)*time.Second)
	resp, err := cl.Get(testURL(x.c))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	n, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, x.c.Watch.TestBytes))
	resp.Body.Close()
	if n < x.c.Watch.TestBytes {
		if copyErr == nil {
			copyErr = fmt.Errorf("получено %d из %d байт", n, x.c.Watch.TestBytes)
		}
		return fmt.Errorf("обрыв на %d байтах: %v", n, copyErr)
	}
	for _, u := range x.c.Watch.CheckURLs {
		resp, err := cl.Get(u)
		if err != nil {
			return fmt.Errorf("%s не открывается: %s", hostOf(u), shortErr(err))
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
		resp.Body.Close()
	}
	return nil
}

// testURL подставляет размер проверки в адрес ({bytes}).
func testURL(c *Config) string {
	return strings.ReplaceAll(c.Watch.TestURL, "{bytes}", strconv.FormatInt(c.Watch.TestBytes, 10))
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return u
}

func (x xrayProbe) latency(port int) (int, error) {
	cl := socksClient(port, time.Duration(x.c.Watch.TimeoutSec)*time.Second)
	start := time.Now()
	resp, err := cl.Get(x.c.Watch.LatencyURL)
	if err != nil {
		return -1, err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return -1, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return int(time.Since(start).Milliseconds()), nil
}

func (x xrayProbe) internetOK() bool {
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	for _, u := range x.c.Watch.DirectURLs {
		if resp, err := cl.Get(u); err == nil {
			resp.Body.Close()
			return true
		}
	}
	return false
}

// probeReady ждёт, пока на пробном входе ядра начнёт отвечать TCP. Сразу после
// старта Xray входы поднимаются не одновременно, и проверки, поспешившие в эту
// гонку, получают connection refused и портят статистику узлов. Дольше secs
// секунд не ждём: лучше пара лишних неудач, чем вечный простой сторожа.
func (x xrayProbe) probeReady(secs int) {
	addr := fmt.Sprintf("127.0.0.1:%d", x.c.Xray.ProbePort)
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if !time.Now().Before(deadline) {
			lg.Printf("пробный вход %s не ответил за %d с — проверки пойдут втёмную", addr, secs)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// override закрепляет балансировщик за узлом (tag="" — снять закрепление).
func (x xrayProbe) override(balancer, tag string) error {
	args := []string{"api", "bo", "-s", x.c.Xray.APIListen, "-b", balancer}
	if tag == "" {
		args = append(args, "-r")
	} else {
		args = append(args, tag)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := runCmd(ctx, nil, x.c.Xray.Bin, args...)
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(tail(out, 2)))
	}
	return nil
}

// setNoNet запоминает, есть ли связь с интернетом. Возвращает true, если состояние
// изменилось: сообщить об этом нужно один раз, а не каждый тик.
func (w *Watcher) setNoNet(down bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.noNet == down {
		return false
	}
	w.noNet = down
	return true
}

// measure обновляет задержку узла. Текст ошибки не трогает: он остаётся от проверки
// загрузкой, которая и решает, рабочий узел или нет.
func (w *Watcher) measure(n *NodeState) {
	ms, _ := w.latency(n.TestPort)
	w.mu.Lock()
	n.LatencyMs, n.CheckedAt = ms, time.Now()
	w.mu.Unlock()
}

// checkAll меряет задержку всех узлов параллельно (по 4 сразу).
func (w *Watcher) checkAll() {
	w.mu.Lock()
	nodes := append(append([]*NodeState(nil), w.nodes...), w.fbs...)
	w.mu.Unlock()
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go safely("замере задержки", func() {
			defer wg.Done()
			defer func() { <-sem }()
			ms, err := w.latency(n.TestPort)
			w.mu.Lock()
			n.LatencyMs, n.CheckedAt = ms, time.Now()
			if err != nil {
				n.LastErr = shortErr(err)
			} else if !strings.HasPrefix(n.LastErr, "залип") {
				n.LastErr = ""
			}
			w.mu.Unlock()
		})
	}
	wg.Wait()
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 120 {
		s = s[i+2:]
	}
	return s
}

// xrayStartTime — отпечаток запущенных процессов ядра (меняется при перезапуске).
func xrayStartTime(c *Config) string { return procStamp(filepath.Base(c.Xray.Bin)) }

// Отпечаток считается обходом всего /proc — на роутере это пара сотен чтений.
// Его спрашивают тик сторожа, самовосстановление и каждый опрос статуса
// веб-страницей (раз в десять секунд на вкладку), поэтому результат кэшируется.
// Срок маленький: по смене отпечатка сторож узнаёт о перезапуске ядра.
const procStampTTL = 2 * time.Second

var procStamps = struct {
	mu  sync.Mutex
	val map[string]string
	at  map[string]time.Time
}{val: map[string]string{}, at: map[string]time.Time{}}

func procStamp(name string) string {
	procStamps.mu.Lock()
	defer procStamps.mu.Unlock()
	if t, ok := procStamps.at[name]; ok && time.Since(t) < procStampTTL {
		return procStamps.val[name]
	}
	v := scanProcStamp(name)
	procStamps.val[name], procStamps.at[name] = v, time.Now()
	return v
}

func scanProcStamp(name string) string {
	if len(name) > 15 {
		name = name[:15] // /proc/*/comm обрезается до 15 символов
	}
	var marks []string
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		comm, err := os.ReadFile(d + "/comm")
		if err != nil || strings.TrimSpace(string(comm)) != name {
			continue
		}
		st, err := os.ReadFile(d + "/stat")
		if err != nil {
			continue
		}
		s := string(st)
		if i := strings.LastIndex(s, ")"); i > 0 {
			f := strings.Fields(s[i+1:])
			if len(f) > 19 {
				marks = append(marks, filepath.Base(d)+":"+f[19])
			}
		}
	}
	sort.Strings(marks)
	return strings.Join(marks, ",")
}
