package main

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// Внешние списки правил приходят в разных форматах. parseRemote определяет
// формат и разбирает его целиком:
//   - голые домены, подсети, geosite:/ext:/regexp: и dnsmasq-строки (как раньше);
//   - классические правила клиентов (surge/shadowrocket/loon/stash/quantumult-x
//     и payload Clash): DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, GEOIP и
//     их HOST-* варианты с третьим полем (all, no-resolve);
//   - типизированные YAML-блоки egern: domain_set, domain_suffix_set,
//     domain_keyword_set, domain_regex_set, ip_cidr_set;
//   - JSON rule-set sing-box: domain, domain_suffix, domain_keyword,
//     domain_regex, ip_cidr (process_name и прочее без эквивалента в Xray
//     пропускаются).

// remoteColl — YAML-ключи, под которыми идёт список значений одного типа.
// payload (Clash) — список классических правил; ключи egern — готовые значения.
var remoteColl = map[string]string{
	"payload":            "classical",
	"domain_set":         "full",
	"domain_suffix_set":  "domain",
	"domain_keyword_set": "keyword",
	"domain_regex_set":   "regexp",
	"ip_cidr_set":        "ip",
}

// parseClientRule переводит классическое правило клиента «ТИП,значение[,параметр]»
// в правило xsub. Покрываются типы с эквивалентом в правилах Xray по домену
// или IP; прочее (PROCESS-NAME, DEST-PORT, …) не маппится — ok=false.
func parseClientRule(line string) (kind, value string, ok bool) {
	t, rest, found := strings.Cut(line, ",")
	if !found {
		return "", "", false
	}
	val, _, _ := strings.Cut(rest, ",") // третье поле (all, no-resolve) не нужно
	val = strings.TrimSpace(val)
	if val == "" {
		return "", "", false
	}
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "DOMAIN", "HOST":
		return "domain", "full:" + strings.ToLower(val), true
	case "DOMAIN-SUFFIX", "HOST-SUFFIX":
		return "domain", "domain:" + strings.ToLower(val), true
	case "DOMAIN-KEYWORD", "HOST-KEYWORD", "KEYWORD":
		return "domain", "keyword:" + strings.ToLower(val), true
	case "IP-CIDR", "IP6-CIDR":
		if _, _, err := net.ParseCIDR(val); err != nil {
			return "", "", false
		}
		return "ip", val, true
	case "GEOIP":
		return "ip", "geoip:" + strings.ToLower(val), true
	}
	return "", "", false
}

// singBoxRuleset — source-правила sing-box (rules/*.json в репозиториях правил).
type singBoxRuleset struct {
	Rules []struct {
		Domain        []string `json:"domain"`
		DomainSuffix  []string `json:"domain_suffix"`
		DomainKeyword []string `json:"domain_keyword"`
		DomainRegex   []string `json:"domain_regex"`
		IPCIDR        []string `json:"ip_cidr"`
	} `json:"rules"`
}

// parseSingBoxRuleset разбирает JSON rule-set sing-box целиком. ok=false —
// это не sing-box JSON или в нём нет ни одного правила.
func parseSingBoxRuleset(text string) (r Rules, ok bool) {
	var rs singBoxRuleset
	if json.Unmarshal([]byte(text), &rs) != nil || len(rs.Rules) == 0 {
		return Rules{}, false
	}
	for _, rule := range rs.Rules {
		for _, d := range rule.Domain {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
				r.Domains = append(r.Domains, "full:"+d)
			}
		}
		for _, d := range rule.DomainSuffix {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
				r.Domains = append(r.Domains, "domain:"+d)
			}
		}
		for _, d := range rule.DomainKeyword {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
				r.Domains = append(r.Domains, "keyword:"+d)
			}
		}
		for _, d := range rule.DomainRegex {
			if d = strings.TrimSpace(d); d != "" {
				r.Domains = append(r.Domains, "regexp:"+d) // регистр значим
			}
		}
		for _, d := range rule.IPCIDR {
			if d = strings.TrimSpace(d); d != "" {
				if _, _, err := net.ParseCIDR(d); err == nil {
					r.IPs = append(r.IPs, d)
				}
			}
		}
	}
	return r, !r.empty()
}

// unquoteRemote снимает кавычки со значения YAML. Для двойных применяются
// escape-правила строки (\\., \", \\ …), как в настоящем YAML.
func unquoteRemote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if q, err := strconv.Unquote(s); err == nil {
			return q
		}
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1] // yaml: '' → '
	}
	return s
}

// isCollKey — строка вида «domain_suffix_set:» (ключ коллекции без значения).
func isCollKey(s string) bool {
	if s == "" || s != strings.ToLower(s) {
		return false
	}
	for _, c := range s {
		if c != '_' && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
