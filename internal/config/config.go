// Package config 实现“期望状态 → 候选配置 → 校验 → 原子发布 → 应用/回滚”
// 的配置事务链（实现方案 §4.1、§4.2）。
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxypanel/internal/core"
	"proxypanel/internal/store"
)

// Providers 提供编译托管配置所需的期望状态。
type Providers struct {
	Settings func() store.Settings
	Nodes    func() []store.NodeRecord
	RuleSets func() []store.RuleSetRecord
}

// Manager 管理配置修订与应用事务。
type Manager struct {
	root     *store.Root
	adapter  core.Adapter
	provider Providers

	mu sync.Mutex // 同主机文件锁：所有改写串行（实现方案 §4.2）

	revisionIndex []store.RevisionMeta
}

// NewManager 创建管理器并加载修订索引。
func NewManager(root *store.Root, adapter core.Adapter, provider Providers) (*Manager, error) {
	m := &Manager{root: root, adapter: adapter, provider: provider}
	if err := root.LoadJSON("revisions.json", &m.revisionIndex); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return m, nil
}

// ---------- 校验（业务级，独立于内核） ----------

// Validate 校验配置 JSON 并返回摘要。
func Validate(content []byte) (string, error) {
	var root struct {
		Log       json.RawMessage  `json:"log"`
		DNS       json.RawMessage  `json:"dns"`
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules   []map[string]any `json:"rules"`
			RuleSet []map[string]any `json:"rule_set"`
			Final   string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(content, &root); err != nil {
		return "", fmt.Errorf("JSON 解析失败：%w", err)
	}
	// 出站 tag 唯一性。
	tags := map[string]bool{}
	for i, ob := range root.Outbounds {
		tag, _ := ob["tag"].(string)
		if tag == "" {
			return "", fmt.Errorf("outbounds[%d] 缺少 tag", i)
		}
		if tags[tag] {
			return "", fmt.Errorf("出站 tag 重复：%s", tag)
		}
		tags[tag] = true
	}
	if len(root.Outbounds) == 0 {
		return "", errors.New("outbounds 不能为空")
	}
	// 入站端口冲突。
	ports := map[int]string{}
	for i, in := range root.Inbounds {
		kind, _ := in["type"].(string)
		listen, _ := in["listen"].(string)
		portNum := 0
		switch v := in["listen_port"].(type) {
		case float64:
			portNum = int(v)
		case int:
			portNum = v
		}
		if portNum == 0 {
			continue
		}
		if prev, ok := ports[portNum]; ok {
			return "", fmt.Errorf("入站端口冲突：%d 同时被 %s 与 inbounds[%d]（%s）使用", portNum, prev, i, listen)
		}
		ports[portNum] = fmt.Sprintf("%s@%s", kind, listen)
	}
	// 路由规则引用检查。
	ruleSetTags := map[string]bool{}
	for i, rs := range root.Route.RuleSet {
		tag, _ := rs["tag"].(string)
		if tag == "" {
			return "", fmt.Errorf("route.rule_set[%d] 缺少 tag", i)
		}
		ruleSetTags[tag] = true
	}
	for i, rule := range root.Route.Rules {
		if ref, ok := rule["rule_set"].([]any); ok {
			for _, item := range ref {
				name, _ := item.(string)
				if name != "" && !ruleSetTags[name] {
					return "", fmt.Errorf("route.rules[%d] 引用了不存在的规则集 %q", i, name)
				}
			}
		}
		for _, field := range []string{"outbound"} {
			if ref, ok := rule[field].(string); ok && ref != "" && !tags[ref] {
				return "", fmt.Errorf("route.rules[%d] 引用了不存在的出站 %q", i, ref)
			}
		}
	}
	if final := root.Route.Final; final != "" && !tags[final] {
		return "", fmt.Errorf("route.final 引用了不存在的出站 %q", final)
	}
	return fmt.Sprintf("配置校验通过：%d 个出站、%d 个入站、%d 条规则、%d 个规则集",
		len(root.Outbounds), len(root.Inbounds), len(root.Route.Rules), len(root.Route.RuleSet)), nil
}

// ---------- 托管编译器 ----------

const (
	manualTag = "manual"
	autoTag   = "auto"
)

// 规则集下载失败时的兜底规则：常见中国顶级域与高频国内网站关键词。
var fallbackCNTLDs = []string{"cn", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "mil.cn", "ac.cn"}
var fallbackCNKeywords = []string{
	"baidu", "qq", "taobao", "alipay", "weixin",
	"163", "sina", "sohu", "douyin", "bilibili",
	"zhihu", "jd", "mi", "huawei", "xiaomi",
}

// CompileManaged 由期望状态编译 sing-box 候选配置。
func CompileManaged(settings store.Settings, nodes []store.NodeRecord, ruleSets []store.RuleSetRecord) ([]byte, string, error) {
	var outbounds []map[string]any
	nodeTags := make([]string, 0, len(nodes))
	for _, n := range nodes {
		var spec map[string]any
		if err := json.Unmarshal(n.Spec, &spec); err != nil {
			return nil, "", fmt.Errorf("节点 %s 的规格无效：%w", n.DisplayName, err)
		}
		outbounds = append(outbounds, spec)
		nodeTags = append(nodeTags, toStringValue(spec["tag"]))
	}

	auto := map[string]any{
		"type": "urltest", "tag": autoTag,
		"outbounds": nodeTags, "url": "https://www.gstatic.com/generate_204", "interval": "5m",
	}
	if len(nodeTags) == 0 {
		auto["outbounds"] = []string{"direct"}
	}
	manualMembers := append([]string{autoTag}, nodeTags...)
	if len(manualMembers) == 1 {
		manualMembers = append(manualMembers, "direct")
	}
	manual := map[string]any{
		"type": "selector", "tag": manualTag, "outbounds": manualMembers, "default": autoTag,
	}
	outbounds = append(outbounds, auto, manual,
		map[string]any{"type": "direct", "tag": "direct"})

	// 入站：混合入站（默认回环）+ 可选 TUN。
	var inbounds []map[string]any
	if settings.MixedPort > 0 {
		listen := "127.0.0.1"
		if settings.LANAccess {
			listen = "::"
		}
		inbounds = append(inbounds, map[string]any{
			"type": "mixed", "tag": "mixed-in", "listen": listen, "listen_port": settings.MixedPort,
		})
	}
	if settings.TUNEnabled {
		// 注意：不写 interface_name，交给 sing-box 自动分配 utunN/tunN。
		// sing-box 1.13 在 macOS 上只接受 utunN 形式的名称，写入任意名称（如 sp-tun）会导致内核启动失败。
		inbounds = append(inbounds, map[string]any{
			"type": "tun", "tag": "tun-in",
			"address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"mtu":     1500, "auto_route": true, "strict_route": true, "stack": "mixed",
		})
	}

	// DNS 预设（实现方案 §5.2；1.13+ 下 DNS 默认直连解析，勿写 detour: direct）。

	// 规则集与基础规则。
	var routeRuleSets []map[string]any
	var geoSiteSets, geoipSets, adsSets []string
	for _, rs := range ruleSets {
		entry := map[string]any{"tag": rs.ID, "format": rs.Format}
		switch {
		case rs.LocalPath != "":
			// 本地缓存优先：内核启动不再依赖外网。
			// （大陆网络直连 raw.githubusercontent.com 超时会导致 sing-box
			// 初始化远程规则集 FATAL 退出。）
			entry["type"] = "local"
			entry["path"] = rs.LocalPath
		case rs.Kind == "remote":
			entry["type"] = "remote"
			entry["url"] = rs.URL
			entry["update_interval"] = rs.Interval
		default:
			entry["type"] = "local"
			entry["path"] = rs.InitialPath
		}
		routeRuleSets = append(routeRuleSets, entry)
		lower := strings.ToLower(rs.Name)
		switch {
		case strings.Contains(lower, "ads"):
			adsSets = append(adsSets, rs.ID)
		case strings.Contains(lower, "geoip") && strings.Contains(lower, "cn"):
			geoipSets = append(geoipSets, rs.ID)
		case strings.Contains(lower, "cn"):
			geoSiteSets = append(geoSiteSets, rs.ID)
		}
	}
	mode := settings.ProxyMode
	if mode == "" {
		mode = "rule"
	}

	// DNS 分流：国内域名用 local-dns（223.5.5.5 UDP）直连解析，避免 DNS 泄露到代理出口。
	dns := buildDNS(settings, geoSiteSets)

	// 基础规则：默认规则模式；global/direct 下跳过规则集匹配，仅保留嗅探与 DNS 直连。
	var rules []map[string]any
	final := manualTag
	switch mode {
	case "global":
		final = manualTag
		rules = []map[string]any{{"action": "sniff"}, {"protocol": "dns", "outbound": "direct"}}
	case "direct":
		final = "direct"
		rules = []map[string]any{{"action": "sniff"}, {"protocol": "dns", "outbound": "direct"}}
	default: // rule
		final = manualTag
		rules = []map[string]any{{"action": "sniff"}}
		if len(settings.ProxyDomains) > 0 {
			// 强制代理域名：优先级高于国内直连规则（如 openlaw.cn 等需要走代理的域名）。
			rules = append(rules, map[string]any{"domain_suffix": settings.ProxyDomains, "outbound": manualTag})
		}
		if len(adsSets) > 0 {
			rules = append(rules, map[string]any{"rule_set": adsSets, "action": "reject"})
		}
		rules = append(rules, map[string]any{"ip_is_private": true, "outbound": "direct"})
		// DNS 协议流量显式直连，防止回落至代理出口。
		rules = append(rules, map[string]any{"protocol": "dns", "outbound": "direct"})
		// 中国 IP 直连（geoip-cn）。
		if len(geoipSets) > 0 {
			rules = append(rules, map[string]any{"rule_set": geoipSets, "outbound": "direct"})
		}
		// 中国域名直连（geosite-cn 等）。
		if len(geoSiteSets) > 0 {
			rules = append(rules, map[string]any{"rule_set": geoSiteSets, "outbound": "direct"})
		} else {
			// 兜底：规则集为空时，通过常见国内域名后缀直连，避免全部流量走代理。
			rules = append(rules, map[string]any{"domain_suffix": fallbackCNTLDs, "outbound": "direct"})
		}
		// 常见国内网站域名关键词兜底（规则集下载失败时仍能保护主流国内流量）。
		rules = append(rules, map[string]any{"domain_keyword": fallbackCNKeywords, "outbound": "direct"})
		rules = append(rules, map[string]any{"protocol": "dns", "action": "sniff"})
	}

	doc := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules":                   rules,
			"rule_set":                routeRuleSets,
			"final":                   final,
			"auto_detect_interface":   true,
			"default_domain_resolver": "bootstrap-dns",
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": "127.0.0.1:9095",
				"default_mode":        mode,
			},
		},
	}
	summary := fmt.Sprintf("托管编译：%d 个节点、%d 个入站、%d 个规则集", len(nodes), len(inbounds), len(routeRuleSets))
	return mustIndent(doc), summary, nil
}

func buildDNS(settings store.Settings, cnSets []string) map[string]any {
	// sing-box >= 1.12.0: 新 DNS 格式，type + server 字段，final 用兜底规则替代。
	// 注意（1.13+）：DNS server 不写 detour 即为直连解析；显式 "detour": "direct" 会触发
	// "detour to an empty direct outbound makes no sense" 启动失败。
	// 国内域名用 local-dns（223.5.5.5 UDP）直连解析，避免 DNS 泄露到代理出口。
	if settings.DNSPreset == "real" {
		dnsRules := buildCNDNSRules(cnSets)
		dnsRules = append(dnsRules, map[string]any{"server": "remote-dns"})
		return map[string]any{
			"servers": []map[string]any{
				{"type": "https", "tag": "remote-dns", "server": "1.1.1.1"},
				{"type": "udp", "tag": "local-dns", "server": "223.5.5.5"},
			},
			"rules":             dnsRules,
			"strategy":          "prefer_ipv4",
			"independent_cache": true,
		}
	}
	// fakeip 模式：国内域名用 local-dns 直连解析，境外域名走 fakeip。
	dnsRules := buildCNDNSRules(cnSets)
	dnsRules = append(dnsRules,
		map[string]any{"query_type": []any{"A", "AAAA"}, "server": "fakeip-dns"},
		map[string]any{"server": "remote-dns"},
	)
	return map[string]any{
		"servers": []map[string]any{
			{"type": "https", "tag": "remote-dns", "server": "1.1.1.1"},
			{"type": "udp", "tag": "bootstrap-dns", "server": "223.5.5.5"},
			{"type": "udp", "tag": "local-dns", "server": "223.5.5.5"},
			{
				"type": "fakeip", "tag": "fakeip-dns",
				"inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18",
			},
		},
		"rules":             dnsRules,
		"independent_cache": true,
	}
}

// buildCNDNSRules 构建国内域名 DNS 分流规则：规则集可用时精确匹配，否则用常见顶级域兜底。
func buildCNDNSRules(cnSets []string) []map[string]any {
	if len(cnSets) > 0 {
		return []map[string]any{
			{"rule_set": cnSets, "server": "local-dns"},
		}
	}
	return []map[string]any{
		{"domain_suffix": fallbackCNTLDs, "server": "local-dns"},
	}
}

func mustIndent(v any) []byte {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return data
}

func toStringValue(v any) string {
	s, _ := v.(string)
	return s
}

// ---------- 修订与事务 ----------

// List 返回修订索引（新→旧）。
func (m *Manager) List() []store.RevisionMeta {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]store.RevisionMeta(nil), m.revisionIndex...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// RevisionConfig 读取指定修订的配置内容。
func (m *Manager) RevisionConfig(id string) ([]byte, error) {
	return os.ReadFile(m.root.Path("revisions", id, "config.json"))
}

// CurrentMode 返回当前配置档形态。
func (m *Manager) CurrentMode() string {
	if s := m.provider.Settings(); s.Mode == "unmanaged" {
		return "unmanaged"
	}
	return "managed"
}

// Apply 提交一次配置变更事务（实现方案 §4.2 六步）。
// source: editor | subscription-update | restore | seed；managed 表示该修订是否为托管编译产物。
func (m *Manager) Apply(ctx context.Context, content []byte, source, createdBy string, managed bool) (store.RevisionMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. 校验（业务级 + 内核 check）。
	summary, err := Validate(content)
	if err != nil {
		return store.RevisionMeta{}, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := m.adapter.Validate(checkCtx, content); err != nil {
		return store.RevisionMeta{}, err
	}

	// 2. 写入不可变草稿版本。
	rev := store.RevisionMeta{
		ID:        fmt.Sprintf("rev-%d", time.Now().UnixMilli()),
		State:     "draft",
		CreatedAt: time.Now().UTC(),
		CreatedBy: createdBy,
		Source:    source,
		Managed:   managed,
		Summary:   summary,
		Checksum:  store.Checksum(content),
	}
	if err := m.root.WriteFileAtomic(filepath.Join("revisions", rev.ID, "config.json"), content); err != nil {
		return rev, err
	}

	// 3. 发布前备份 last-known-good。
	previous, hasPrevious := m.readRuntime()

	// 4. 原子发布到 runtime。
	if err := m.root.WriteFileAtomic(filepath.Join("runtime", "config.json"), content); err != nil {
		rev.State = "failed"
		rev.Error = err.Error()
		m.recordRevision(rev)
		return rev, err
	}

	// 5. 通过适配器应用 + 健康探针。
	applyCtx, applyCancel := context.WithTimeout(ctx, 20*time.Second)
	defer applyCancel()
	applyErr := m.adapter.ApplyRevision(applyCtx, core.Revision{ID: rev.ID, Content: content})
	if applyErr == nil {
		applyErr = m.adapter.HealthCheck(applyCtx)
	}
	if applyErr != nil {
		// 6. 失败回滚：恢复上一份文件并重新应用（实现方案 §4.2）。
		rev.State = "failed"
		rev.Error = applyErr.Error()
		if hasPrevious {
			_ = m.root.WriteFileAtomic(filepath.Join("runtime", "config.json"), previous)
			rollbackCtx, rollbackCancel := context.WithTimeout(ctx, 20*time.Second)
			defer rollbackCancel()
			_ = m.adapter.ApplyRevision(rollbackCtx, core.Revision{ID: "rollback", Content: previous})
		} else {
			_ = os.Remove(m.root.Path("runtime", "config.json"))
		}
		m.recordRevision(rev)
		return rev, fmt.Errorf("配置应用失败（已回滚）：%w", applyErr)
	}

	rev.State = "applied"
	if hasPrevious {
		_ = m.root.WriteFileAtomic(filepath.Join("runtime", "last-known-good.json"), previous)
	}
	m.recordRevision(rev)
	m.pruneRevisions()
	return rev, nil
}

func (m *Manager) readRuntime() ([]byte, bool) {
	data, err := os.ReadFile(m.root.Path("runtime", "config.json"))
	return data, err == nil
}

func (m *Manager) recordRevision(rev store.RevisionMeta) {
	m.revisionIndex = append(m.revisionIndex, rev)
	_ = m.root.SaveJSON("revisions.json", m.revisionIndex)
	_ = m.root.SaveJSON(filepath.Join("revisions", rev.ID, "meta.json"), rev)
}

func (m *Manager) pruneRevisions() {
	const keep = 10
	var applied []int
	for i, rev := range m.revisionIndex {
		if rev.State == "applied" {
			applied = append(applied, i)
		}
	}
	if len(applied) <= keep {
		return
	}
	for _, idx := range applied[:len(applied)-keep] {
		rev := m.revisionIndex[idx]
		_ = os.RemoveAll(m.root.Path("revisions", rev.ID))
		m.revisionIndex = append(m.revisionIndex[:idx], m.revisionIndex[idx+1:]...)
	}
	_ = m.root.SaveJSON("revisions.json", m.revisionIndex)
}

// CompileAndApply 编译托管配置并走完整事务；nodes/ruleSets 来自 Providers。
func (m *Manager) CompileAndApply(ctx context.Context, createdBy, source string) (store.RevisionMeta, error) {
	rev, err := m.Apply(ctx, m.compileFromProviders(), source, createdBy, true)
	return rev, err
}

func (m *Manager) compileFromProviders() []byte {
	content, _, err := CompileManaged(m.provider.Settings(), m.provider.Nodes(), m.provider.RuleSets())
	if err != nil {
		return []byte("{}")
	}
	return content
}

// Restore 从历史修订创建新修订并应用（恢复不能覆盖历史，实现方案 §5.6）。
func (m *Manager) Restore(ctx context.Context, id, createdBy string) (store.RevisionMeta, error) {
	content, err := m.RevisionConfig(id)
	if err != nil {
		return store.RevisionMeta{}, fmt.Errorf("修订 %s 不存在：%w", id, err)
	}
	if _, err := Validate(content); err != nil {
		return store.RevisionMeta{}, fmt.Errorf("历史修订未通过现行校验：%w", err)
	}
	managed := m.CurrentMode() == "managed"
	return m.Apply(ctx, content, "restore", createdBy, managed)
}

// LastApplied 返回最近一次成功应用的修订（无则 nil）。
func (m *Manager) LastApplied() *store.RevisionMeta {
	for i := len(m.revisionIndex) - 1; i >= 0; i-- {
		if m.revisionIndex[i].State == "applied" {
			rev := m.revisionIndex[i]
			return &rev
		}
	}
	return nil
}
