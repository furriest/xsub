package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// errTelegramAPI — Telegram ответил, но отказал (токен, chat_id): повторять
// через VPN бессмысленно. Отличается от сетевой ошибки через errors.Is.
var errTelegramAPI = errors.New("ответ Telegram")

// Notifier отправляет уведомления в Telegram. api.telegram.org в России часто недоступен
// напрямую, поэтому при неудаче сообщение уходит через VPN (локальный вход Xray).
type Notifier struct {
	c    *Config
	mu   sync.Mutex
	last map[string]time.Time
	hour []time.Time // отправленные за последний час (ограничение на случай «дребезга»)
}

func newNotifier(c *Config) *Notifier { return &Notifier{c: c, last: map[string]time.Time{}} }

func (n *Notifier) enabled() bool { return n.c.Telegram.Token != "" && n.c.Telegram.ChatID != "" }

// send отправляет сообщение, если с прошлого сообщения с тем же ключом прошло не меньше gap
// (gap=0 — не чаще раза в 2 минуты). Отправка идёт в фоне.
func (n *Notifier) send(key, text string, gap time.Duration) {
	if !n.enabled() {
		return
	}
	if gap == 0 {
		gap = 2 * time.Minute
	}
	n.mu.Lock()
	now := time.Now()
	if t, ok := n.last[key]; ok && now.Sub(t) < gap {
		n.mu.Unlock()
		return
	}
	var recent []time.Time
	for _, t := range n.hour {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 20 {
		n.hour = recent
		n.mu.Unlock()
		return
	}
	n.last[key] = now
	n.hour = append(recent, now)
	n.mu.Unlock()
	goSafe("отправке в Telegram", func() {
		if err := n.post(text); err != nil {
			lg.Printf("Telegram: %v", err)
		}
	})
}

func (n *Notifier) post(text string) error {
	host, _ := os.Hostname()
	if host != "" {
		text = "xsub (" + host + "): " + text
	} else {
		text = "xsub: " + text
	}
	form := url.Values{"chat_id": {n.c.Telegram.ChatID}, "text": {text}, "disable_web_page_preview": {"true"}}
	api := "https://api.telegram.org/bot" + n.c.Telegram.Token + "/sendMessage"
	try := func(proxyPort int) error {
		tr := &http.Transport{DisableKeepAlives: true}
		if proxyPort > 0 {
			tr.Proxy = http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", proxyPort)})
		}
		cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
		resp, err := cl.PostForm(api, form)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var r struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		_ = json.Unmarshal(b, &r)
		if !r.OK {
			return fmt.Errorf("%w: %s", errTelegramAPI, firstNonEmpty(r.Description, resp.Status))
		}
		return nil
	}
	err := try(0)
	if err == nil {
		return nil
	}
	if errors.Is(err, errTelegramAPI) {
		return err // токен или chat_id неверные — через VPN не поможет
	}
	if err2 := try(n.c.Xray.ProbePort); err2 != nil {
		return fmt.Errorf("напрямую: %v; через VPN: %v", cleanErr(err), cleanErr(err2))
	}
	return nil
}

// test — проверочное сообщение с веб-страницы (синхронно, с ошибкой).
func (n *Notifier) test() error {
	if !n.enabled() {
		return fmt.Errorf("укажите токен бота и chat_id")
	}
	return n.post("проверочное сообщение — уведомления работают")
}
