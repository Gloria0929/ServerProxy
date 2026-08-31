package config

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxypanel/internal/core"
	"proxypanel/internal/store"
)

func validConfig() []byte {
	return []byte(`{
		"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 7897}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"rules": [], "final": "direct"}
	}`)
}

type stubAdapter struct {
	failApply bool
	applied   []string
}

func (s *stubAdapter) GetStatus(context.Context) (core.Status, error) { return core.Status{}, nil }
func (s *stubAdapter) ListGroups(context.Context) ([]core.Group, error) {
	return nil, nil
}
func (s *stubAdapter) SelectNode(context.Context, string, string) error { return nil }
func (s *stubAdapter) TestDelay(context.Context) (int, error)           { return 0, nil }
func (s *stubAdapter) ListConnections(context.Context) ([]core.Connection, error) {
	return nil, nil
}
func (s *stubAdapter) CloseConnection(context.Context, string) error { return nil }
func (s *stubAdapter) StreamLogs(context.Context) (<-chan core.LogLine, error) {
	ch := make(chan core.LogLine)
	close(ch)
	return ch, nil
}
func (s *stubAdapter) Validate(_ context.Context, content []byte) error {
	return json.Unmarshal(content, new(map[string]any))
}
func (s *stubAdapter) ApplyRevision(_ context.Context, rev core.Revision) error {
	if s.failApply {
		s.failApply = false
		return errors.New("模拟内核 reload 失败")
	}
	s.applied = append(s.applied, rev.ID)
	return nil
}
func (s *stubAdapter) GetCapabilities(context.Context) core.Capabilities { return core.Capabilities{} }
func (s *stubAdapter) HealthCheck(context.Context) error                 { return nil }
func (s *stubAdapter) Restart(context.Context) error                     { return nil }

func newTestManager(t *testing.T, adapter core.Adapter) *Manager {
	t.Helper()
	root, err := store.New(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(root, adapter, Providers{
		Settings: store.DefaultSettings,
		Nodes:    func() []store.NodeRecord { return nil },
		RuleSets: func() []store.RuleSetRecord { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"重复tag", `{"outbounds":[{"type":"direct","tag":"a"},{"type":"direct","tag":"a"}]}`, "tag 重复"},
		{"空outbounds", `{"outbounds":[]}`, "outbounds 不能为空"},
		{"端口冲突", `{"inbounds":[{"type":"mixed","tag":"a","listen_port":7897},{"type":"mixed","tag":"b","listen_port":7897}],"outbounds":[{"type":"direct","tag":"direct"}]}`, "端口冲突"},
		{"规则引用不存在出站", `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"outbound":"missing"}]}}`, "不存在的出站"},
		{"规则引用不存在规则集", `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"rule_set":["ads"],"outbound":"direct"}]}}`, "不存在的规则集"},
		{"final引用不存在", `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"nope"}}`, "final 引用"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate([]byte(tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want contains %q", err, tc.want)
			}
		})
	}
	if _, err := Validate(validConfig()); err != nil {
		t.Fatalf("合法配置校验失败：%v", err)
	}
}

func TestApplySuccessAndRollback(t *testing.T) {
	adapter := &stubAdapter{}
	m := newTestManager(t, adapter)

	// 第一次应用成功。
	rev1, err := m.Apply(context.Background(), validConfig(), "editor", "web", false)
	if err != nil {
		t.Fatalf("apply1: %v", err)
	}
	if rev1.State != "applied" {
		t.Fatalf("state = %s", rev1.State)
	}
	published, err := os.ReadFile(m.root.Path("runtime", "config.json"))
	if err != nil || !strings.Contains(string(published), "direct") {
		t.Fatalf("runtime 配置未发布: %v", err)
	}

	// 第二次应用失败 → 自动回滚到第一份。
	adapter.failApply = true
	rev2, err := m.Apply(context.Background(), []byte(`{"outbounds":[{"type":"direct","tag":"direct2"}]}`), "editor", "web", false)
	if err == nil {
		t.Fatal("第二次应用应失败")
	}
	if rev2.State != "failed" {
		t.Fatalf("state = %s", rev2.State)
	}
	// runtime 已回滚为第一份内容。
	rolled, err := os.ReadFile(m.root.Path("runtime", "config.json"))
	if err != nil || !strings.Contains(string(rolled), `"tag": "direct"`) || strings.Contains(string(rolled), "direct2") {
		t.Fatalf("回滚后 runtime 内容异常: %s (%v)", rolled, err)
	}
	// last-known-good 备份存在。
	if _, err := os.Stat(m.root.Path("runtime", "last-known-good.json")); err != nil {
		t.Fatalf("缺少 last-known-good: %v", err)
	}
}

func TestApplyBlocksInvalidBeforePublish(t *testing.T) {
	adapter := &stubAdapter{}
	m := newTestManager(t, adapter)
	_, err := m.Apply(context.Background(), []byte(`{"outbounds":[{"type":"direct","tag":"dup"},{"type":"direct","tag":"dup"}]}`), "editor", "web", false)
	if err == nil {
		t.Fatal("无效配置应在发布前被阻断")
	}
	if _, err := os.Stat(m.root.Path("runtime", "config.json")); !os.IsNotExist(err) {
		t.Fatal("无效配置不应产生 runtime 发布物")
	}
}

func TestRestoreCreatesNewRevision(t *testing.T) {
	adapter := &stubAdapter{}
	m := newTestManager(t, adapter)
	rev1, err := m.Apply(context.Background(), validConfig(), "editor", "web", false)
	if err != nil {
		t.Fatal(err)
	}
	rev2, err := m.Apply(context.Background(), []byte(`{"outbounds":[{"type":"direct","tag":"other"}],"route":{"final":"other"}}`), "editor", "web", false)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := m.Restore(context.Background(), rev1.ID, "web")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.ID == rev1.ID || restored.ID == rev2.ID {
		t.Fatal("恢复必须创建新修订")
	}
	if restored.Source != "restore" || restored.State != "applied" {
		t.Fatalf("restored = %+v", restored)
	}
}

func TestCompileManagedShape(t *testing.T) {
	nodes := []store.NodeRecord{{
		Fingerprint: "fp1", DisplayName: "香港 01", Type: "trojan",
		Spec: []byte(`{"type":"trojan","tag":"sub-abc","server":"hk.example.com","server_port":443,"password":"pw"}`),
	}}
	ruleSets := []store.RuleSetRecord{
		{
			ID: "geosite-cn", Name: "geosite-cn", Kind: "remote", Format: "binary",
			URL: "https://example.com/cn.srs", Interval: "24h", InitialPath: "rules/cn.srs",
		},
		{
			ID: "geoip-cn", Name: "geoip-cn", Kind: "remote", Format: "binary",
			URL: "https://example.com/geoip-cn.srs", Interval: "24h", InitialPath: "rules/geoip-cn.srs",
		},
		{
			ID: "geosite-category-ads-all", Name: "geosite-category-ads-all", Kind: "remote", Format: "binary",
			URL: "https://example.com/ads.srs", Interval: "24h", InitialPath: "rules/ads.srs",
		},
	}
	settings := store.DefaultSettings()
	settings.TUNEnabled = true
	content, summary, err := CompileManaged(settings, nodes, ruleSets)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "1 个节点") {
		t.Errorf("summary = %s", summary)
	}
	var doc struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			RuleSet []map[string]any `json:"rule_set"`
			Rules   []map[string]any `json:"rules"`
			Final   string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Inbounds) != 2 { // mixed + tun
		t.Errorf("inbounds = %d, want 2", len(doc.Inbounds))
	}
	if doc.Route.Final != manualTag {
		t.Errorf("final = %s", doc.Route.Final)
	}
	if len(doc.Route.RuleSet) != 3 {
		t.Errorf("rule_set = %d, want 3", len(doc.Route.RuleSet))
	}
	// 验证规则包含 geoip-cn
	foundGeoIP := false
	for _, rule := range doc.Route.Rules {
		if rs, ok := rule["rule_set"].([]any); ok {
			for _, r := range rs {
				if r == "geoip-cn" {
					foundGeoIP = true
				}
			}
		}
	}
	if !foundGeoIP {
		t.Error("route rules should contain geoip-cn rule set")
	}
	// 编译产物必须通过自身校验。
	if _, err := Validate(content); err != nil {
		t.Fatalf("编译产物未通过校验: %v", err)
	}
}

// TestCompileManagedFallbackWithoutCNRules 验证规则集为空时的兜底逻辑。
func TestCompileManagedFallbackWithoutCNRules(t *testing.T) {
	nodes := []store.NodeRecord{{
		Fingerprint: "fp1", DisplayName: "香港 01", Type: "trojan",
		Spec: []byte(`{"type":"trojan","tag":"sub-abc","server":"hk.example.com","server_port":443,"password":"pw"}`),
	}}
	// 仅广告规则集，无中国相关规则集 — 触发兜底逻辑。
	ruleSets := []store.RuleSetRecord{
		{
			ID: "geosite-category-ads-all", Name: "geosite-category-ads-all", Kind: "remote", Format: "binary",
			URL: "https://example.com/ads.srs", Interval: "24h", InitialPath: "rules/ads.srs",
		},
	}
	settings := store.DefaultSettings()
	content, _, err := CompileManaged(settings, nodes, ruleSets)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
		DNS struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatal(err)
	}
	// 验证回退规则包含 domain_suffix（中国顶级域）。
	foundFallback := false
	for _, rule := range doc.Route.Rules {
		if ds, ok := rule["domain_suffix"].([]any); ok {
			for _, d := range ds {
				if d == "cn" {
					foundFallback = true
				}
			}
		}
	}
	if !foundFallback {
		t.Error("route rules should contain domain_suffix fallback for cn when CN rule sets are empty")
	}
	// 验证 DNS 回退包含 domain_suffix。
	foundDNSFallback := false
	for _, rule := range doc.DNS.Rules {
		if ds, ok := rule["domain_suffix"].([]any); ok {
			for _, d := range ds {
				if d == "cn" {
					foundDNSFallback = true
				}
			}
		}
	}
	if !foundDNSFallback {
		t.Error("DNS rules should contain domain_suffix fallback when CN rule sets are empty")
	}
	// 验证 domain_keyword 兜底规则存在。
	foundKeyword := false
	for _, rule := range doc.Route.Rules {
		if _, ok := rule["domain_keyword"]; ok {
			foundKeyword = true
		}
	}
	if !foundKeyword {
		t.Error("route rules should contain domain_keyword fallback")
	}
	if _, err := Validate(content); err != nil {
		t.Fatalf("编译产物未通过校验: %v", err)
	}
}

// TestCompileManagedDNSSplit 验证 DNS 分流：国内域名走 local-dns，其余走 fakeip。
func TestCompileManagedDNSSplit(t *testing.T) {
	nodes := []store.NodeRecord{{
		Fingerprint: "fp1", DisplayName: "香港 01", Type: "trojan",
		Spec: []byte(`{"type":"trojan","tag":"sub-abc","server":"hk.example.com","server_port":443,"password":"pw"}`),
	}}
	ruleSets := []store.RuleSetRecord{
		{
			ID: "geosite-cn", Name: "geosite-cn", Kind: "remote", Format: "binary",
			URL: "https://example.com/cn.srs", Interval: "24h", InitialPath: "rules/cn.srs",
		},
	}
	settings := store.DefaultSettings()
	content, _, err := CompileManaged(settings, nodes, ruleSets)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatal(err)
	}
	// 验证 DNS 服务器包含 local-dns。
	foundLocalDNS := false
	for _, srv := range doc.DNS.Servers {
		if tag, ok := srv["tag"].(string); ok && tag == "local-dns" {
			foundLocalDNS = true
		}
	}
	if !foundLocalDNS {
		t.Error("DNS servers should contain local-dns")
	}
	// 验证 DNS 规则包含 CN 分流（rule_set → local-dns）。
	foundCNRule := false
	for _, rule := range doc.DNS.Rules {
		if rs, ok := rule["rule_set"].([]any); ok {
			for _, r := range rs {
				if r == "geosite-cn" {
					if srv, ok := rule["server"].(string); ok && srv == "local-dns" {
						foundCNRule = true
					}
				}
			}
		}
	}
	if !foundCNRule {
		t.Error("DNS rules should route CN domains to local-dns")
	}
	// 验证 fakeip 规则存在。
	foundFakeIP := false
	for _, rule := range doc.DNS.Rules {
		if srv, ok := rule["server"].(string); ok && srv == "fakeip-dns" {
			foundFakeIP = true
		}
	}
	if !foundFakeIP {
		t.Error("DNS rules should contain fakeip-dns for foreign domains")
	}
	if _, err := Validate(content); err != nil {
		t.Fatalf("编译产物未通过校验: %v", err)
	}
}
