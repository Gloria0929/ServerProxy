// 订阅管理：HTTP 获取 → 格式识别 → 解析 → 去重 → 快照（实现方案 §5.3）。
// 获取失败时保留上一次成功快照，绝不清空现有节点。
package subscription

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"proxypanel/internal/store"
)

const maxBodySize = 4 << 20 // 订阅内容大小上限（实现方案 §7.6）

// Manager 管理订阅 CRUD、更新流水线与快照。
type Manager struct {
	root         *store.Root
	keys         *store.Keyring
	client       *http.Client
	mu           sync.Mutex      // 按订阅 URL 串行更新（实现方案 §5.3）
	allowPrivate map[string]bool // 管理员明确批准可访问内网的主机
	allowMu      sync.RWMutex
}

// NewManager 创建订阅管理器。client 应为 nil 时使用内置 SSRF 防护传输。
func NewManager(root *store.Root, keys *store.Keyring) *Manager {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		// DialContext 在连接建立后校验对端地址，防 SSRF（实现方案 §7.5）。
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			remote := conn.RemoteAddr()
			host, _, splitErr := net.SplitHostPort(remote.String())
			if splitErr != nil {
				host = remote.String()
			}
			ip := net.ParseIP(host)
			if ip != nil && isBlockedIP(ip) {
				conn.Close()
				return nil, fmt.Errorf("订阅抓取禁止访问内网/环回地址：%s（可在设置中明确批准）", host)
			}
			return conn, nil
		},
		// 订阅源常有自签证书，跳过 TLS 证书校验；SSRF 地址校验仍在 DialContext 生效。
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &Manager{
		root:         root,
		keys:         keys,
		client:       &http.Client{Timeout: 30 * time.Second, Transport: transport},
		allowPrivate: map[string]bool{},
	}
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified()
}

// AllowPrivateHost 记录管理员明确批准的内网主机。
func (m *Manager) AllowPrivateHost(host string) {
	m.allowMu.Lock()
	defer m.allowMu.Unlock()
	m.allowPrivate[strings.ToLower(host)] = true
}

// List 返回全部订阅。
func (m *Manager) List() []store.Subscription {
	m.mu.Lock()
	defer m.mu.Unlock()
	subs := m.load()
	if subs == nil {
		subs = []store.Subscription{}
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
	return subs
}

func (m *Manager) load() []store.Subscription {
	var subs []store.Subscription
	if err := m.root.LoadJSON("subscriptions.json", &subs); err != nil {
		return nil
	}
	return subs
}

func (m *Manager) save(subs []store.Subscription) error {
	return m.root.SaveJSON("subscriptions.json", subs)
}

// PreviewURL 返回脱敏 URL：协议 + 主机 + 末 4 位路径（实现方案 §3.1）。
func (m *Manager) PreviewURL(sub store.Subscription) string {
	raw, err := m.keys.Decrypt(sub.URLCipher)
	if err != nil {
		return "（无法解密）"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "（无效地址）"
	}
	host := u.Hostname()
	if u.Port() != "" {
		host += ":" + u.Port()
	}
	tail := ""
	if p := u.Path; len(p) > 4 {
		tail = "…" + p[len(p)-4:]
	} else {
		tail = p
	}
	return fmt.Sprintf("%s://%s%s", u.Scheme, host, tail)
}

// Add 新建订阅并立即尝试一次更新。
func (m *Manager) Add(ctx context.Context, name, rawURL, schedule string) (store.Subscription, error) {
	if name == "" || rawURL == "" {
		return store.Subscription{}, errors.New("名称与地址不能为空")
	}
	if u, err := url.Parse(rawURL); err != nil || u.Scheme == "" || u.Host == "" {
		return store.Subscription{}, errors.New("订阅地址无效")
	}
	if schedule == "" {
		schedule = "每 6 小时"
	}
	cipher, err := m.keys.Encrypt(rawURL)
	if err != nil {
		return store.Subscription{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	subs := m.load()
	for _, s := range subs {
		if s.URLCipher == cipher {
			return store.Subscription{}, errors.New("该订阅地址已存在")
		}
	}
	sub := store.Subscription{
		ID:         fmt.Sprintf("sub-%d", time.Now().UnixMilli()),
		Name:       name,
		URLCipher:  cipher,
		Schedule:   schedule,
		Enabled:    true,
		LastStatus: "pending",
	}
	subs = append(subs, sub)
	if err := m.save(subs); err != nil {
		return store.Subscription{}, err
	}
	return sub, nil
}

// Delete 删除订阅（快照保留供审计）。
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	subs := m.load()
	found := false
	out := subs[:0]
	for _, s := range subs {
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

// Patch 更新订阅的名称/频率/启用状态；传入了新 URL 时重新加密并重置解析状态。
func (m *Manager) Patch(id, name, rawURL, schedule string, enabled *bool) (store.Subscription, error) {
	if name == "" {
		return store.Subscription{}, errors.New("名称不能为空")
	}
	if schedule == "" {
		schedule = "每 6 小时"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	subs := m.load()
	index := -1
	for i, s := range subs {
		if s.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return store.Subscription{}, store.ErrNotFound
	}
	sub := subs[index]
	sub.Name = name
	sub.Schedule = schedule
	if enabled != nil {
		sub.Enabled = *enabled
	}
	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return store.Subscription{}, errors.New("订阅地址无效")
		}
		cipher, err := m.keys.Encrypt(rawURL)
		if err != nil {
			return store.Subscription{}, err
		}
		sub.URLCipher = cipher
		// URL 变更后清空条件缓存与旧状态，等待下次更新。
		sub.ETag = ""
		sub.LastModified = ""
		sub.LastStatus = "pending"
		sub.LastError = ""
	}
	subs[index] = sub
	if err := m.save(subs); err != nil {
		return store.Subscription{}, err
	}
	return sub, nil
}

// URL 解密并返回订阅的完整地址，仅供编辑时回显。
func (m *Manager) URL(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.load() {
		if s.ID == id {
			return m.keys.Decrypt(s.URLCipher)
		}
	}
	return "", store.ErrNotFound
}

// Update 获取并解析订阅；失败返回错误但不改动现有节点。
func (m *Manager) Update(ctx context.Context, id string) (*ParseResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	subs := m.load()
	index := -1
	for i, s := range subs {
		if s.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, store.ErrNotFound
	}
	sub := subs[index]
	rawURL, err := m.keys.Decrypt(sub.URLCipher)
	if err != nil {
		return nil, fmt.Errorf("解密订阅地址失败：%w", err)
	}

	data, etag, lastModified, err := m.fetch(ctx, rawURL, sub.ETag, sub.LastModified)
	if err != nil {
		sub.LastStatus = "failed"
		sub.LastError = err.Error()
		subs[index] = sub
		_ = m.save(subs)
		m.writeSnapshot(sub, nil, err)
		return nil, err
	}
	if len(data) == 0 { // 304 Not Modified
		sub.LastStatus = "ok"
		sub.LastError = ""
		sub.LastUpdated = time.Now()
		subs[index] = sub
		_ = m.save(subs)
		return nil, nil
	}

	result, err := ParsePayload(data)
	if err != nil {
		sub.LastStatus = "failed"
		sub.LastError = err.Error()
		subs[index] = sub
		_ = m.save(subs)
		m.writeSnapshot(sub, map[string]any{"error": err.Error(), "fetched_at": time.Now().UTC()}, errors.New(err.Error()))
		return nil, err
	}
	// 记录节点归属订阅，供前端按订阅筛选。
	for i := range result.Nodes {
		result.Nodes[i].SubID = sub.ID
	}

	sub.LastStatus = "ok"
	sub.LastError = ""
	sub.ETag = etag
	sub.LastModified = lastModified
	sub.LastUpdated = time.Now()
	sub.NodeCount = len(result.Nodes)
	sub.Warnings = len(result.Warnings)
	subs[index] = sub
	if err := m.save(subs); err != nil {
		return nil, err
	}
	if err := m.root.SaveJSON("nodes/"+sub.ID+".json", result.Nodes); err != nil {
		return nil, err
	}
	m.writeSnapshot(sub, map[string]any{
		"fetched_at": sub.LastUpdated.UTC(),
		"format":     result.Format,
		"sha256":     store.Checksum(data),
		"node_count": len(result.Nodes),
		"warnings":   result.Warnings,
	}, nil)
	return result, nil
}

// userAgents 是订阅请求的 UA 候选：部分机场按 UA 白名单分发内容（只认 Clash/Mihomo 系客户端，
// 或按 UA 返回不同格式），面板自报 UA 会被 502/403 拒绝。按序降级重试，首个成功者生效。
var userAgents = []string{
	"clash-verge/v2.0.2",
	"mihomo/v1.19.1",
	"ClashforWindows/0.20.39",
}

// fetch 依次尝试不同 UA 的条件请求；304 返回空数据。
func (m *Manager) fetch(ctx context.Context, rawURL, etag, lastModified string) ([]byte, string, string, error) {
	var lastErr error
	for _, ua := range userAgents {
		data, nextETag, nextLM, err := m.fetchWithUA(ctx, rawURL, ua, etag, lastModified)
		if err == nil {
			return data, nextETag, nextLM, nil
		}
		lastErr = err
	}
	return nil, "", "", lastErr
}

func (m *Manager) fetchWithUA(ctx context.Context, rawURL, ua, etag, lastModified string) ([]byte, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("订阅地址无效：%w", redactURLError(err))
	}
	req.Header.Set("User-Agent", ua)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, "", "", fmt.Errorf("订阅获取失败：%w", redactURLError(err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, etag, lastModified, nil
	case resp.StatusCode != http.StatusOK:
		return nil, "", "", fmt.Errorf("订阅服务器返回 %s（UA %s）", resp.Status, ua)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return nil, "", "", fmt.Errorf("读取订阅内容失败：%w", err)
	}
	if len(data) > maxBodySize {
		return nil, "", "", fmt.Errorf("订阅内容超过 %d MB 上限", maxBodySize>>20)
	}
	return data, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), nil
}

// redactURLError 去除错误信息中 URL 的查询参数与凭据，避免订阅 token 泄露到日志/存储。
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %q: %w", ue.Op, redactURL(ue.URL), ue.Err)
	}
	return err
}

// redactURL 与 PreviewURL 的脱敏口径一致：只保留 scheme://host 和路径末 4 位，
// 丢弃查询串、fragment 与用户信息。
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	tail := u.Path
	if len(tail) > 4 {
		tail = "…" + tail[len(tail)-4:]
	}
	u.User = nil
	u.Path = tail
	u.RawQuery = ""
	u.RawFragment = ""
	return u.String()
}

func (m *Manager) writeSnapshot(sub store.Subscription, payload map[string]any, fetchErr error) {
	if payload == nil {
		payload = map[string]any{"fetched_at": time.Now().UTC(), "error": fetchErr.Error()}
	}
	dir := "snapshots/" + sub.ID
	_ = os.MkdirAll(m.root.Path(dir), 0o700)
	name := fmt.Sprintf("%d.json", time.Now().Unix())
	// 只保留最近 5 份快照。
	entries, _ := os.ReadDir(m.root.Path(dir))
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) >= 5 {
		_ = os.Remove(m.root.Path(dir, names[0]))
		names = names[1:]
	}
	_ = m.root.SaveJSON(dir+"/"+name, payload)
}

// NodesFor 返回某订阅最近一次成功解析的节点。
func (m *Manager) NodesFor(subID string) []store.NodeRecord {
	var nodes []store.NodeRecord
	if err := m.root.LoadJSON("nodes/"+subID+".json", &nodes); err != nil {
		return nil
	}
	// 兼容旧数据：订阅归属以文件名 ID 为准。
	for i := range nodes {
		if nodes[i].SubID == "" {
			nodes[i].SubID = subID
		}
	}
	return nodes
}

// AllNodes 汇总全部订阅的节点。
func (m *Manager) AllNodes() []store.NodeRecord {
	var out []store.NodeRecord
	for _, sub := range m.List() {
		out = append(out, m.NodesFor(sub.ID)...)
	}
	return out
}

// ScheduleInterval 把计划字符串映射为更新周期；低于 6 小时按 6 小时。
func ScheduleInterval(schedule string) time.Duration {
	switch schedule {
	case "每小时":
		return 6 * time.Hour
	case "每天":
		return 24 * time.Hour
	default:
		return 6 * time.Hour
	}
}
