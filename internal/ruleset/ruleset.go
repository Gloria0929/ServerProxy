// Package ruleset 管理远程/本地规则集（实现方案 §5.4）：
// 原生 remote 类型、显式 format/url/interval、初始本地缓存、
// 连续失败告警而不删除最后可用缓存。
package ruleset

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"proxypanel/internal/observability"
	"proxypanel/internal/store"
)

const maxRuleSetSize = 16 << 20

// Manager 管理规则集记录与更新。
type Manager struct {
	root     *store.Root
	client   *http.Client
	logs     *observability.LogBuffer
	mu       sync.Mutex
	failures map[string]int
}

// NewManager 创建规则集管理器。
func NewManager(root *store.Root, logs *observability.LogBuffer) *Manager {
	return &Manager{
		root:     root,
		logs:     logs,
		failures: map[string]int{},
		client:   &http.Client{Timeout: 60 * time.Second},
	}
}

func (m *Manager) load() []store.RuleSetRecord {
	var sets []store.RuleSetRecord
	if err := m.root.LoadJSON("rule_sets.json", &sets); err != nil {
		return nil
	}
	return sets
}

func (m *Manager) save(sets []store.RuleSetRecord) error {
	return m.root.SaveJSON("rule_sets.json", sets)
}

// List 返回全部规则集；本地缓存存在时回填 LocalPath，供托管编译优先使用本地引用。
func (m *Manager) List() []store.RuleSetRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	sets := m.load()
	if sets == nil {
		sets = []store.RuleSetRecord{}
	}
	for i := range sets {
		if sets[i].InitialPath != "" {
			if _, err := os.Stat(m.root.Path(sets[i].InitialPath)); err == nil {
				sets[i].LocalPath = sets[i].InitialPath
			}
		}
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].Name < sets[j].Name })
	return sets
}

// mirrorFromRaw 把 raw.githubusercontent.com 地址换成 jsDelivr 镜像：
// 大陆网络直连 GitHub Raw 超时会导致内核规则集初始化失败，jsDelivr 通常可达。
func mirrorFromRaw(raw string) string {
	const prefix = "https://raw.githubusercontent.com/"
	if !strings.HasPrefix(raw, prefix) {
		return raw
	}
	rest := strings.TrimPrefix(raw, prefix) // user/repo/branch/path...
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 {
		return raw
	}
	return "https://cdn.jsdelivr.net/gh/" + parts[0] + "/" + parts[1] + "@" + parts[2]
}

// SeedDefaults 首次运行时注入两个常用规则集（使用大陆可达的 jsDelivr 源），
// 并顺带把已有记录里的旧 GitHub Raw 地址迁移到镜像。
func (m *Manager) SeedDefaults() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sets := m.load()
	if sets == nil {
		sets = []store.RuleSetRecord{
			{
				ID: "geosite-geolocation-cn", Name: "geosite-geolocation-cn",
				Kind: "remote", Format: "binary",
				URL:      "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
				Interval: "24h", InitialPath: "rules/geosite-geolocation-cn.srs",
				Status: "pending",
			},
			{
				ID: "geosite-category-ads-all", Name: "geosite-category-ads-all",
				Kind: "remote", Format: "binary",
				URL:      "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ads-all.srs",
				Interval: "24h", InitialPath: "rules/geosite-category-ads-all.srs",
				Status: "pending",
			},
		}
		return m.save(sets)
	}
	// 迁移旧 GitHub Raw 源（幂等）。
	dirty := false
	for i := range sets {
		if mirrored := mirrorFromRaw(sets[i].URL); mirrored != sets[i].URL {
			sets[i].URL = mirrored
			dirty = true
		}
	}
	if dirty {
		return m.save(sets)
	}
	return nil
}

// Add 新增远程规则集；格式必须为 sing-box source/binary（实现方案 §5.4）。
func (m *Manager) Add(name, rawURL, format, interval string) (store.RuleSetRecord, error) {
	if name == "" || rawURL == "" {
		return store.RuleSetRecord{}, errors.New("名称与地址不能为空")
	}
	if format != "source" && format != "binary" {
		return store.RuleSetRecord{}, fmt.Errorf("规则集格式 %q 不受支持（仅 source/binary）", format)
	}
	if interval == "" {
		interval = "24h"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sets := m.load()
	for _, s := range sets {
		if s.Name == name {
			return store.RuleSetRecord{}, errors.New("同名规则集已存在")
		}
	}
	record := store.RuleSetRecord{
		ID: name, Name: name, Kind: "remote", Format: format,
		URL: rawURL, Interval: interval,
		InitialPath: "rules/" + name + ".srs",
		Status:      "pending",
	}
	sets = append(sets, record)
	return record, m.save(sets)
}

// Delete 删除规则集（缓存保留）。
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sets := m.load()
	found := false
	out := sets[:0]
	for _, s := range sets {
		if s.ID == id {
			found = true
			continue
		}
		out = append(out, s)
	}
	if !found {
		return store.ErrNotFound
	}
	return m.save(out)
}

// Update 拉取远程规则集并写缓存；失败不删除旧缓存。
func (m *Manager) Update(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sets := m.load()
	index := -1
	for i, s := range sets {
		if s.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return store.ErrNotFound
	}
	rs := sets[index]
	if rs.Kind != "remote" {
		rs.Status = "ok"
		sets[index] = rs
		return m.save(sets)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rs.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ServerProxy/0.1 (rule-set updater)")
	if rs.ETag != "" {
		req.Header.Set("If-None-Match", rs.ETag)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return m.markFailure(sets, index, rs, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		rs.Status = "ok"
		rs.LastUpdated = time.Now()
	case resp.StatusCode != http.StatusOK:
		err = fmt.Errorf("规则源返回 %s", resp.Status)
		return m.markFailure(sets, index, rs, err)
	default:
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxRuleSetSize))
		if err != nil {
			return m.markFailure(sets, index, rs, err)
		}
		if err := m.root.WriteFileAtomic(rs.InitialPath, data); err != nil {
			return m.markFailure(sets, index, rs, err)
		}
		rs.Status = "ok"
		rs.Hash = store.Checksum(data)
		rs.ETag = resp.Header.Get("ETag")
		rs.LastUpdated = time.Now()
		m.failures[rs.ID] = 0
		m.logs.Append("info", "rule-set", "规则集 "+rs.Name+" 已更新（sha256:"+short(rs.Hash)+"）")
	}
	sets[index] = rs
	return m.save(sets)
}

// markFailure 记录失败；连续三次触发告警事件，不删除缓存。
func (m *Manager) markFailure(sets []store.RuleSetRecord, index int, rs store.RuleSetRecord, cause error) error {
	rs.Status = "failed"
	rs.LastError = cause.Error()
	sets[index] = rs
	_ = m.save(sets)
	m.failures[rs.ID]++
	if m.failures[rs.ID] >= 3 {
		m.logs.Append("error", "rule-set", fmt.Sprintf("规则集 %s 连续 %d 次更新失败：%v（保留最后可用缓存）", rs.Name, m.failures[rs.ID], cause))
		m.failures[rs.ID] = 0 // 触发一次告警后重新计数
	} else {
		m.logs.Append("warn", "rule-set", "规则集 "+rs.Name+" 更新失败："+cause.Error())
	}
	return cause
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// DueInterval 解析更新周期字符串。
func DueInterval(interval string) time.Duration {
	if d, err := time.ParseDuration(interval); err == nil && d >= time.Hour {
		return d
	}
	return 24 * time.Hour
}
