package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Чтение категорий из geosite.dat / geoip.dat (формат protobuf v2fly) без сторонних библиотек.
// Файл читается потоком: в память попадает только нужная категория.

type geoDomain struct {
	typ   int            // 0 — подстрока (keyword), 1 — регулярное выражение, 2 — домен с поддоменами, 3 — точное имя
	value string         // для типов 0, 2 и 3 уже в нижнем регистре
	re    *regexp.Regexp // для типа 1; компилируется один раз при загрузке категории
	attrs []string
}

// Категория geosite — это до сотен тысяч записей, и на роутере со 128 МБ памяти
// держать их все подряд нельзя. Кэш помнит порядок обращений и вытесняет самые
// давние. Бюджет — по суммарному числу записей, а не по числу категорий: одна
// категория может съесть памяти больше, чем десять мелких.
const (
	maxGeoSiteEntries = 250_000
	maxGeoIPEntries   = 50_000
)

type geoCacheT struct {
	mu       sync.Mutex
	site     map[string][]geoDomain
	ip       map[string][]*net.IPNet
	siteKeys []string
	ipKeys   []string
	siteN    int // суммарно записей в кэше каждого вида — по ним считается бюджет
	ipN      int
}

var geoCache = &geoCacheT{}

func (g *geoCacheT) reset() {
	g.mu.Lock()
	g.site, g.ip = nil, nil
	g.siteKeys, g.ipKeys = nil, nil
	g.siteN, g.ipN = 0, 0
	g.mu.Unlock()
}

// putSite кладёт категорию в кэш, вытесняя самые давние, пока суммарное число
// записей не влезет в бюджет. Категория одна больше бюджета — остаётся: иначе
// кэш вообще не работал бы, а цикл вытеснения стал бы бесконечным. Под g.mu.
func (g *geoCacheT) putSite(key string, d []geoDomain) {
	if g.site == nil {
		g.site = map[string][]geoDomain{}
	}
	if old, ok := g.site[key]; ok {
		g.siteN -= len(old)
	} else {
		g.siteKeys = append(g.siteKeys, key)
	}
	g.site[key] = d
	g.siteN += len(d)
	for g.siteN > maxGeoSiteEntries && len(g.siteKeys) > 1 {
		oldest := g.siteKeys[0]
		g.siteN -= len(g.site[oldest])
		delete(g.site, oldest)
		g.siteKeys = g.siteKeys[1:]
	}
}

// putIP — то же для категорий geoip. Под g.mu.
func (g *geoCacheT) putIP(key string, n []*net.IPNet) {
	if g.ip == nil {
		g.ip = map[string][]*net.IPNet{}
	}
	if old, ok := g.ip[key]; ok {
		g.ipN -= len(old)
	} else {
		g.ipKeys = append(g.ipKeys, key)
	}
	g.ip[key] = n
	g.ipN += len(n)
	for g.ipN > maxGeoIPEntries && len(g.ipKeys) > 1 {
		oldest := g.ipKeys[0]
		g.ipN -= len(g.ip[oldest])
		delete(g.ip, oldest)
		g.ipKeys = g.ipKeys[1:]
	}
}

func readVarint(r *bufio.Reader) (uint64, error) { return binary.ReadUvarint(r) }

// Границы на длины из файла: varint приходит из geo-файла, который мы скачали по
// ссылке из конфига. У битого или подменённого файла длина может быть любой, а
// make([]byte, l) на такой длине — это паника, которая на роутере роняет демон.
const (
	maxGeoEntry = 128 << 20 // запись верхнего уровня: категория целиком
	maxGeoCode  = 1 << 10   // код категории — короткая строка
)

// forEachEntry проходит по записям верхнего уровня (поле 1) и отдаёт код категории и тело записи,
// если want(код) == true; остальные записи пропускаются без чтения в память.
func forEachEntry(path string, want func(code string) bool, fn func(code string, body []byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	// Читатель тела записи: один на весь проход, на каждой записи переставляется
	// через Reset. Строить его поверх r нельзя — bufio.NewReader от *bufio.Reader
	// с достаточным буфером возвращает тот же объект, и чтение замкнётся само на себя.
	br := bufio.NewReaderSize(nil, 4<<10)
	for {
		key, err := readVarint(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if key&7 != 2 {
			return fmt.Errorf("неожиданный формат %s", filepath.Base(path))
		}
		size, err := readVarint(r)
		if err != nil {
			return err
		}
		if size > maxGeoEntry {
			return fmt.Errorf("%s: запись длиной %d байт — файл повреждён", filepath.Base(path), size)
		}
		// первое поле записи — код категории (строка, поле 1)
		lr := io.LimitReader(r, int64(size))
		br.Reset(lr)
		k, err := readVarint(br)
		if err != nil {
			return err
		}
		if k != (1<<3 | 2) {
			_, _ = io.Copy(io.Discard, br) // br читает через lr — выбирается и то и другое
			continue
		}
		l, err := readVarint(br)
		if err != nil {
			return err
		}
		if l > maxGeoCode {
			return fmt.Errorf("%s: код категории длиной %d байт — файл повреждён", filepath.Base(path), l)
		}
		codeB := make([]byte, l)
		if _, err := io.ReadFull(br, codeB); err != nil {
			return err
		}
		code := string(codeB)
		if !want(code) {
			_, _ = io.Copy(io.Discard, br)
			continue
		}
		rest, err := io.ReadAll(br)
		if err != nil {
			return err
		}
		if err := fn(code, rest); err != nil {
			return err
		}
	}
}

// fields разбирает тело сообщения protobuf: вызывает fn для каждого поля.
func fields(b []byte, fn func(num int, wire int, v uint64, data []byte) error) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return errors.New("битый protobuf")
		}
		b = b[n:]
		num, wire := int(key>>3), int(key&7)
		switch wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return errors.New("битый protobuf")
			}
			b = b[n:]
			if err := fn(num, wire, v, nil); err != nil {
				return err
			}
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return errors.New("битый protobuf")
			}
			data := b[n : n+int(l)]
			b = b[n+int(l):]
			if err := fn(num, wire, 0, data); err != nil {
				return err
			}
		case 5:
			if len(b) < 4 {
				return errors.New("битый protobuf")
			}
			b = b[4:]
		case 1:
			if len(b) < 8 {
				return errors.New("битый protobuf")
			}
			b = b[8:]
		default:
			return errors.New("битый protobuf")
		}
	}
	return nil
}

// geoSite возвращает правила категории из файла (имя без пути, в папке assetdir).
func geoSite(c *Config, file, cat string) ([]geoDomain, error) {
	cat = strings.ToUpper(cat)
	key := file + ":" + cat
	geoCache.mu.Lock()
	if d, ok := geoCache.site[key]; ok {
		geoCache.mu.Unlock()
		return d, nil
	}
	geoCache.mu.Unlock()
	var out []geoDomain
	found := false
	err := forEachEntry(filepath.Join(c.Xray.AssetDir, file),
		func(code string) bool { return strings.EqualFold(code, cat) },
		func(_ string, body []byte) error {
			found = true
			// поля GeoSite после кода: 2 — Domain
			return fields(body, func(num, wire int, _ uint64, data []byte) error {
				if num != 2 || wire != 2 {
					return nil
				}
				var d geoDomain
				err := fields(data, func(n, w int, v uint64, dd []byte) error {
					switch {
					case n == 1 && w == 0:
						d.typ = int(v)
					case n == 2 && w == 2:
						d.value = string(dd)
					case n == 3 && w == 2: // Attribute { key = 1 }
						_ = fields(dd, func(an, aw int, _ uint64, ad []byte) error {
							if an == 1 && aw == 2 {
								d.attrs = append(d.attrs, string(ad))
							}
							return nil
						})
					}
					return nil
				})
				// Регулярное выражение компилируется один раз на запись, остальные
				// значения приводятся к нижнему регистру — иначе это делалось бы
				// заново для каждого проверяемого домена.
				if d.typ == 1 {
					d.re, _ = regexp.Compile(d.value)
				} else {
					d.value = strings.ToLower(d.value)
				}
				out = append(out, d)
				return err
			})
		})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("в %s нет категории %s", file, cat)
	}
	geoCache.mu.Lock()
	geoCache.putSite(key, out)
	geoCache.mu.Unlock()
	return out, nil
}

func geoIP(c *Config, file, cat string) ([]*net.IPNet, error) {
	cat = strings.ToUpper(cat)
	key := file + ":" + cat
	geoCache.mu.Lock()
	if d, ok := geoCache.ip[key]; ok {
		geoCache.mu.Unlock()
		return d, nil
	}
	geoCache.mu.Unlock()
	var out []*net.IPNet
	found := false
	err := forEachEntry(filepath.Join(c.Xray.AssetDir, file),
		func(code string) bool { return strings.EqualFold(code, cat) },
		func(_ string, body []byte) error {
			found = true
			return fields(body, func(num, wire int, _ uint64, data []byte) error {
				if num != 2 || wire != 2 {
					return nil
				}
				var ip []byte
				var prefix int
				_ = fields(data, func(n, w int, v uint64, dd []byte) error {
					switch {
					case n == 1 && w == 2:
						ip = append([]byte(nil), dd...)
					case n == 2 && w == 0:
						prefix = int(v)
					}
					return nil
				})
				if len(ip) == 4 || len(ip) == 16 {
					out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, len(ip)*8)})
				}
				return nil
			})
		})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("в %s нет категории %s", file, cat)
	}
	geoCache.mu.Lock()
	geoCache.putIP(key, out)
	geoCache.mu.Unlock()
	return out, nil
}
