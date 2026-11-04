package main

import (
	"strings"
	"testing"
)

// Внешние списки понимаются целиком во всех распространённых форматах
// (репозиторий VPSDance/ai-proxy-rules — эталонный набор таких файлов).
func TestParseRemoteClientRules(t *testing.T) {
	text := `# header
DOMAIN,exact.example.com
DOMAIN-SUFFIX,sub.example.com
DOMAIN-KEYWORD,keywordexample
IP-CIDR,203.0.113.0/24,no-resolve
GEOIP,ru
PROCESS-NAME,chrome
`
	r, skipped := parseRemote(text)
	wantD := []string{"full:exact.example.com", "domain:sub.example.com", "keyword:keywordexample"}
	if strings.Join(r.Domains, ",") != strings.Join(wantD, ",") {
		t.Fatalf("domains: %v", r.Domains)
	}
	if strings.Join(r.IPs, ",") != "203.0.113.0/24,geoip:ru" {
		t.Fatalf("ips: %v", r.IPs)
	}
	if skipped != 1 { // PROCESS-NAME не маппится
		t.Fatalf("skipped: %d", skipped)
	}
}

func TestParseRemoteQuantumult(t *testing.T) {
	r, _ := parseRemote("HOST-SUFFIX,example.com,all\nHOST,exact.example.com,тег\n")
	if strings.Join(r.Domains, ",") != "domain:example.com,full:exact.example.com" {
		t.Fatalf("%v", r.Domains)
	}
}

func TestParseRemoteClashPayload(t *testing.T) {
	text := `payload:
  # комментарий
  - DOMAIN-SUFFIX,openai.com
  - DOMAIN,chat.openai.com
  - IP-CIDR,198.51.100.0/24
`
	r, skipped := parseRemote(text)
	wantD := []string{"domain:openai.com", "full:chat.openai.com"}
	if strings.Join(r.Domains, ",") != strings.Join(wantD, ",") {
		t.Fatalf("domains: %v", r.Domains)
	}
	if strings.Join(r.IPs, ",") != "198.51.100.0/24" {
		t.Fatalf("ips: %v", r.IPs)
	}
	if skipped != 0 {
		t.Fatalf("skipped: %d", skipped)
	}
}

func TestParseRemoteEgernYaml(t *testing.T) {
	text := `no_resolve: true
domain_set:
  - "exact.example.com"
domain_suffix_set:
  - "suffix.example.com"
domain_keyword_set:
  - "KeywordExample"
domain_regex_set:
  - "^ads\\."
ip_cidr_set:
  - "2001:db8::/32"
asn_set:
  - "64512"
`
	r, _ := parseRemote(text)
	wantD := []string{
		"full:exact.example.com",
		"domain:suffix.example.com",
		"keyword:keywordexample",
		`regexp:^ads\.`,
	}
	if strings.Join(r.Domains, ",") != strings.Join(wantD, ",") {
		t.Fatalf("domains: %v", r.Domains)
	}
	if strings.Join(r.IPs, ",") != "2001:db8::/32" {
		t.Fatalf("ips: %v", r.IPs)
	}
}

func TestParseRemoteSingBoxJSON(t *testing.T) {
	text := `{
  "version": 2,
  "rules": [
    {"domain": ["Exact.example.com"], "domain_suffix": ["suffix.example.com"]},
    {"domain_keyword": ["kwexample"], "domain_regex": ["^track\\."], "ip_cidr": ["192.0.2.0/24"]},
    {"process_name": ["helper"]}
  ]
}`
	r, skipped := parseRemote(text)
	wantD := []string{
		"full:exact.example.com",
		"domain:suffix.example.com",
		"keyword:kwexample",
		`regexp:^track\.`,
	}
	if strings.Join(r.Domains, ",") != strings.Join(wantD, ",") {
		t.Fatalf("domains: %v", r.Domains)
	}
	if strings.Join(r.IPs, ",") != "192.0.2.0/24" {
		t.Fatalf("ips: %v", r.IPs)
	}
	if skipped != 0 {
		t.Fatalf("skipped: %d", skipped)
	}
}

// Прежние формы внешних списков продолжают работать.
func TestParseRemotePlainUnchanged(t *testing.T) {
	text := "example.com\n=exact.example.com\n*.wild.example.com\n1.2.3.0/24\ngeosite:telegram\nserver=/dnsmasq.example/1.1.1.1\n"
	r, skipped := parseRemote(text)
	wantD := []string{"domain:example.com", "full:exact.example.com", "domain:wild.example.com", "geosite:telegram", "domain:dnsmasq.example"}
	if strings.Join(r.Domains, ",") != strings.Join(wantD, ",") {
		t.Fatalf("domains: %v", r.Domains)
	}
	if strings.Join(r.IPs, ",") != "1.2.3.0/24" {
		t.Fatalf("ips: %v", r.IPs)
	}
	if skipped != 0 {
		t.Fatalf("skipped: %d", skipped)
	}
}
