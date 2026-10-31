package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Logger держит последние строки в памяти (их показывает веб-страница) и, если задан файл,
// дописывает их туда. По умолчанию файл в /tmp — это оперативная память роутера,
// флеш-память и USB-накопитель не изнашиваются. Дескриптор держим открытым:
// write уходит в kernel сразу (как раньше при open/write/close), но без двух
// лишних syscall'ов на каждую строку.
type Logger struct {
	mu      sync.Mutex
	path    string
	maxSize int64 // при превышении файл становится .old, предыдущий .old удаляется
	ring    []string
	f       *os.File
}

const ringSize = 300

var lg = &Logger{maxSize: 256 << 10}

func (l *Logger) Printf(format string, a ...any) {
	line := time.Now().Format("2006-01-02 15:04:05") + " " + fmt.Sprintf(format, a...)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring = append(l.ring, line)
	if len(l.ring) > ringSize {
		l.ring = l.ring[len(l.ring)-ringSize:]
	}
	if l.path == "" {
		return
	}
	l.write(line)
}

// write дописывает строку, при необходимости ротируя журнал. Под l.mu.
func (l *Logger) write(line string) {
	if l.f != nil {
		if st, err := l.f.Stat(); err == nil && st.Size() > l.maxSize {
			l.closeLocked()
			_ = os.Rename(l.path, l.path+".old")
		}
	}
	if l.f == nil {
		_ = os.MkdirAll(filepath.Dir(l.path), 0o755)
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		l.f = f
	}
	if _, err := fmt.Fprintln(l.f, line); err != nil {
		// Дескриптор протух — следующая строка откроет файл заново.
		l.closeLocked()
	}
}

func (l *Logger) closeLocked() {
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}

// Close освобождает дескриптор журнала — при штатной остановке и перед exit.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeLocked()
}

func (l *Logger) Tail(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.ring) {
		n = len(l.ring)
	}
	out := make([]string, n)
	copy(out, l.ring[len(l.ring)-n:])
	return out
}

// safely выполняет f, не давая панике уронить демон: xsub работает на роутере,
// где его некому поднять — упавший сторож означает, что узлы перестали переключаться.
// Паника пишется в журнал вместе с началом стека, остальное продолжает работать.
func safely(what string, f func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		lg.Printf("внутренняя ошибка в %s: %v\n%s", what, r, headLines(string(debug.Stack()), 15))
	}()
	f()
}

// goSafe — safely в отдельной горутине.
func goSafe(what string, f func()) { go safely(what, f) }

// headLines оставляет первые n строк — у стека паники интересно начало, а не хвост.
func headLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = append(lines[:n:n], "…")
	}
	return strings.Join(lines, "\n")
}
