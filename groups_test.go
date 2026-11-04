package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// «Напрямую»-группа: свои домены уходят в direct-outbound, балансировщика,
// пробного входа и сторожа у группы нет. Обычная группа рядом не страдает.
func TestGenerateDirectGroup(t *testing.T) {
	c := defaultConfig()
	c.Xray.ConfDir = t.TempDir()
	writeConf(t, c.Xray.ConfDir, map[string]string{
		"03_inbounds.json": `{"inbounds":[{"tag":"redirect","port":1,"protocol":"dokodemo-door"}]}`,
	})
	nodes, _ := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{})
	gs := []Group{
		{ID: "g1", Name: "AI напрямую", Direct: true},
		{ID: "g2", Name: "Anthropic", Filter: "(?i)netherlands"},
	}
	rs := RouteSet{
		Direct: Rules{Domains: []string{"domain:direct.example"}},
		Groups: []GroupRules{
			{Group: gs[0], Rules: Rules{Domains: []string{"domain:ai-direct.example"}}},
			{Group: gs[1], Rules: Rules{Domains: []string{"domain:anthropic.com"}}},
		},
		VPN: Rules{Domains: []string{"domain:vpn.example"}},
	}
	env, err := scanEnv(c)
	if err != nil {
		t.Fatal(err)
	}
	routing, xsub, err := generate(c, env, nodes, nil, rs)
	if err != nil {
		t.Fatal(err)
	}
	r, x := string(routing), string(xsub)
	// Правило «напрямую»-группы есть и идёт на direct, а не на балансировщик.
	if !strings.Contains(r, "domain:ai-direct.example") || !strings.Contains(r, "xsub-direct") {
		t.Errorf("нет правила прямой группы на direct:\n%s", r)
	}
	// Балансировщик и пробный вход — только у обычной группы; у прямой — ничего.
	if strings.Contains(r, "xsub-g1") || strings.Contains(x, "xsub-probe-g1") {
		t.Errorf("у прямой группы не должно быть балансировщика и пробного входа:\n%s\n%s", r, x)
	}
	if !strings.Contains(r, `"tag": "xsub-g2"`) || !strings.Contains(x, "xsub-probe-g2") {
		t.Errorf("у обычной группы балансировщик и пробный вход потерялись:\n%s\n%s", r, x)
	}
}

// Порядок групп в groups.json = порядок правил: при перекрывающихся списках
// выигрывает та группа, что стоит раньше.
func TestGenerateGroupsOrder(t *testing.T) {
	c := defaultConfig()
	c.Xray.ConfDir = t.TempDir()
	writeConf(t, c.Xray.ConfDir, map[string]string{
		"03_inbounds.json": `{"inbounds":[{"tag":"redirect","port":1,"protocol":"dokodemo-door"}]}`,
	})
	nodes, _ := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{})
	grp := func(id, dom string) GroupRules {
		return GroupRules{Group: Group{ID: id, Name: id, Filter: "(?i)netherlands"}, Rules: Rules{Domains: []string{"domain:" + dom}}}
	}
	env, _ := scanEnv(c)
	rs := RouteSet{Groups: []GroupRules{grp("g1", "same.example"), grp("g2", "same.example")}}
	r1, _, err := generate(c, env, nodes, nil, rs)
	if err != nil {
		t.Fatal(err)
	}
	i1 := strings.Index(string(r1), `"xsub-g1"`)
	i2 := strings.Index(string(r1), `"xsub-g2"`)
	if i1 < 0 || i2 < 0 || i1 > i2 {
		t.Fatalf("порядок правил не по порядку групп: g1@%d g2@%d", i1, i2)
	}
	// Поменяли местами — поменялся и порядок правил.
	rs.Groups = []GroupRules{rs.Groups[1], rs.Groups[0]}
	r2, _, _ := generate(c, env, nodes, nil, rs)
	j1 := strings.Index(string(r2), `"xsub-g2"`)
	j2 := strings.Index(string(r2), `"xsub-g1"`)
	if j1 < 0 || j2 < 0 || j1 > j2 {
		t.Fatalf("порядок не перевернулся: g2@%d g1@%d", j1, j2)
	}
}

// Резерв на группу: балансировщик группы получает выбранный fallbackTag,
// остальные — общий; ссылка на удалённый резерв молча игнорируется.
func TestGenerateGroupFallback(t *testing.T) {
	c := defaultConfig()
	c.Xray.ConfDir = t.TempDir()
	writeConf(t, c.Xray.ConfDir, map[string]string{
		"03_inbounds.json": `{"inbounds":[{"tag":"redirect","port":1,"protocol":"dokodemo-door"}]}`,
	})
	nodes, _ := parseSubscription(decodeSubscription([]byte(sampleSub())), parseOpts{})
	fbNode1 := mkNode("fb-aaaaaaaa", "Резерв A")
	fbNode1.Outbound = map[string]any{"tag": "fb-aaaaaaaa", "protocol": "freedom"}
	fbNode2 := mkNode("fb-bbbbbbbb", "Резерв B")
	fbNode2.Outbound = map[string]any{"tag": "fb-bbbbbbbb", "protocol": "freedom"}
	rs := RouteSet{Groups: []GroupRules{
		{Group: Group{ID: "g1", Name: "G1", Filter: "(?i)netherlands", Fallback: "fb-bbbbbbbb"}, Rules: Rules{Domains: []string{"domain:g1.example"}}},
		{Group: Group{ID: "g2", Name: "G2", Filter: "(?i)netherlands", Fallback: "fb-удалён"}, Rules: Rules{Domains: []string{"domain:g2.example"}}},
	}}
	env, _ := scanEnv(c)
	r, _, err := generate(c, env, nodes, []Node{fbNode1, fbNode2}, rs)
	if err != nil {
		t.Fatal(err)
	}
	s := string(r)
	i := strings.Index(s, `"balancers"`)
	j := strings.Index(s[i:], `"rules"`)
	bals := s[i : i+j]
	// Резерв B — только у g1; общий резерв A — у основной цели и у g2.
	if strings.Count(bals, "fb-bbbbbbbb") != 1 {
		t.Errorf("выбранный резерв должен быть только у g1:\n%s", bals)
	}
	if strings.Count(bals, "fb-aaaaaaaa") != 2 {
		t.Errorf("общий резерв должен быть у основной цели и у g2:\n%s", bals)
	}
}

func TestCheckTargetDirectGroup(t *testing.T) {
	a := checkTestApp(t, map[string]string{
		"vpn.txt":      "ai-direct.example\n",
		"groups.json":  `[{"id":"g1","name":"AI напрямую","direct":true}]`,
		"group-g1.txt": "ai-direct.example\n",
	})
	res := a.checkTarget("ai-direct.example")
	if res.Route != "direct" || !strings.Contains(res.Target, "AI напрямую") {
		t.Fatalf("route=%q target=%q list=%q", res.Route, res.Target, res.List)
	}
}

// saveGroups принимает содержимое списков и сохраняет порядок групп как есть.
func TestSaveGroupsWithLists(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	c.Xray.Bin = fakeXray(t)
	c.Xray.RestartCmd = "true"
	a, err := newApp(c)
	if err != nil {
		t.Fatal(err)
	}
	gs := []Group{
		{ID: "g1", Name: "Вторая", Filter: "x"},
		{ID: "g2", Name: "Первая", Direct: true},
	}
	lists := map[string]string{"g1": "one.example\n", "g2": "two.example\n"}
	if err := a.saveGroups(gs, lists, true); err != nil {
		t.Fatal(err)
	}
	got, err := loadGroups(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "g1" || got[1].ID != "g2" || !got[1].Direct {
		t.Fatalf("порядок/флаги не сохранились: %+v", got)
	}
	for id, want := range lists {
		b, err := os.ReadFile(c.path(groupListName(id)))
		if err != nil || string(b) != want {
			t.Fatalf("список %s: %q %v", id, b, err)
		}
	}
	// Битый список отклоняется до любых записей.
	bad := map[string]string{"g1": "плохо но!!\n"}
	if err := a.saveGroups(gs, bad, true); err == nil {
		t.Fatal("битый список должен отклоняться")
	}
	if b, _ := os.ReadFile(c.path(groupListName("g1"))); string(b) != "one.example\n" {
		t.Fatalf("файл испорчен неудачным сохранением: %q", b)
	}

	// Резерв группы должен существовать.
	if err := os.WriteFile(c.path(fallbacksFile), []byte(`[{"name":"R","link":"vless://`+tUUID+`@res.example.com:443?encryption=none&security=reality&sni=a.example&pbk=4oPjFhCGYBbtVD2aCoA4x3EULVckDGWQYjvci2tp6Jo"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	gf := []Group{{ID: "g3", Name: "G3", Filter: "x", Fallback: "fb-нет-такого"}}
	if err := a.saveGroups(gf, nil, false); err == nil {
		t.Fatal("несуществующий резерв группы должен отклоняться")
	}
	fbNow, _ := fallbackNodes(c, nil)
	if len(fbNow) != 1 {
		t.Fatalf("резерв: %+v", fbNow)
	}
	gf[0].Fallback = fbNow[0].Tag
	if err := a.saveGroups(gf, nil, false); err != nil {
		t.Fatalf("существующий резерв должен приниматься: %v", err)
	}
	_ = context.Background
}
