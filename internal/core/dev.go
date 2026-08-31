package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

// DevAdapter 是开发阶段的内核适配器：不触碰本机 TUN、路由表或 nftables，
// 在内存中模拟 sing-box 的策略组、连接、流量与重载行为（对应设置页说明）。
// 接入真实内核时以 SingBoxAdapter 实现同一 Adapter 接口替换。
type DevAdapter struct {
	mu         sync.RWMutex
	startedAt  time.Time
	core       string
	groups     []Group
	nodeIndex  map[string]*nodeState
	traffic    Traffic
	uploadTB   float64
	downloadTB float64
	conns      map[string]*Connection
	nextPort   int
	logger     func(LogLine)
}

type nodeState struct {
	node Node
	base int
}

// NewDevAdapter 创建开发适配器；节点由调用方通过 SetNodes 注入（订阅解析结果）。
func NewDevAdapter() *DevAdapter {
	a := &DevAdapter{
		startedAt: time.Now(),
		core:      "sing-box 1.12.0-dev (adapter=simulated)",
		conns:     make(map[string]*Connection),
		nextPort:  40000,
		nodeIndex: make(map[string]*nodeState),
		traffic:   Traffic{},
	}
	return a
}

// SetLogger 注册内核日志回调，由可观测层转发到环形缓冲。
func (a *DevAdapter) SetLogger(fn func(LogLine)) { a.logger = fn }

// SetNodes 用真实节点（来自订阅解析）重建策略组，替代演示假数据。
func (a *DevAdapter) SetNodes(nodes []Node) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rebuildGroupsLocked(nodes)
}

func (a *DevAdapter) rebuildGroupsLocked(nodes []Node) {
	a.nodeIndex = make(map[string]*nodeState, len(nodes))
	realNodes := make([]Node, len(nodes))
	for i, n := range nodes {
		if n.ID == "" {
			n.ID = fmt.Sprintf("node-%d", i+1)
		}
		if n.Name == "" {
			n.Name = n.ID
		}
		base := n.Latency
		if base <= 0 {
			base = 60
		}
		n.Latency = base
		n.Available = true
		realNodes[i] = n
		a.nodeIndex[n.ID] = &nodeState{node: n, base: base}
	}
	sort.Slice(realNodes, func(i, j int) bool { return realNodes[i].Name < realNodes[j].Name })

	if len(realNodes) == 0 {
		a.groups = []Group{}
		return
	}
	auto := Group{Tag: "auto", Name: "自动选择", Type: "urltest", Selected: realNodes[0].ID, Nodes: append([]Node(nil), realNodes...)}
	manualNodes := append([]Node{{
		ID: "auto", Name: "自动选择", Protocol: "urltest", Region: "策略", Latency: realNodes[0].Latency, Available: true,
	}}, realNodes...)
	manual := Group{Tag: "manual", Name: "手动选择", Type: "selector", Selected: realNodes[0].ID, Nodes: manualNodes}
	a.groups = []Group{manual, auto}
}

// GetStatus 实现内核状态采样。
func (a *DevAdapter) GetStatus(ctx context.Context) (Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	mem := &runtime.MemStats{}
	runtime.ReadMemStats(mem)
	return Status{
		CoreVersion:   a.core,
		Running:       true,
		StartedAt:     a.startedAt,
		UptimeSeconds: int64(time.Since(a.startedAt).Seconds()),
		CurrentProxy:  a.currentProxyLocked(),
		Mode:          "rule",
		Traffic:       a.traffic,
		Resources: Resources{
			MemoryMB:   int(mem.Alloc / 1024 / 1024),
			Goroutines: runtime.NumGoroutine(),
			TUN:        "开发适配器（未启用）",
		},
	}, nil
}

func (a *DevAdapter) currentProxyLocked() string {
	for _, g := range a.groups {
		if g.Type == "selector" {
			for _, n := range g.Nodes {
				if n.ID == g.Selected {
					return g.Name + " → " + n.Name
				}
			}
		}
	}
	return "direct"
}

// ListGroups 实现策略组查询。
func (a *DevAdapter) ListGroups(ctx context.Context) ([]Group, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Group, 0, len(a.groups))
	for _, g := range a.groups {
		g.Nodes = append([]Node(nil), g.Nodes...)
		out = append(out, g)
	}
	return out, nil
}

// SelectNode 仅更新 selector 的当前选择，不触发重载（实现方案 §6.1）。
func (a *DevAdapter) SelectNode(ctx context.Context, groupTag, nodeID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.groups {
		g := &a.groups[i]
		if g.Tag != groupTag {
			continue
		}
		if g.Type != "selector" {
			return fmt.Errorf("策略组 %s 类型为 %s，不支持手动切换", g.Name, g.Type)
		}
		for _, n := range g.Nodes {
			if n.ID == nodeID {
				g.Selected = nodeID
				if a.logger != nil {
					a.logger(LogLine{Time: time.Now(), Level: "info", Component: "clash-api", Message: "selector " + g.Name + " 切换到 " + n.Name})
				}
				return nil
			}
		}
		return fmt.Errorf("节点 %s 不存在", nodeID)
	}
	return fmt.Errorf("策略组 %s 不存在", groupTag)
}

// SetMode 切换代理模式（开发适配器：仅记录日志）。
func (a *DevAdapter) SetMode(ctx context.Context, mode string) error {
	if a.logger != nil {
		a.logger(LogLine{Time: time.Now(), Level: "info", Component: "control-plane", Message: "代理模式已切换为 " + mode})
	}
	return nil
}

// TestDelay 并发模拟延迟测试，返回更新节点数。
func (a *DevAdapter) TestDelay(ctx context.Context) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, st := range a.nodeIndex {
		jitter := rand.IntN(18) - 9
		st.node.Latency = max(1, st.base+jitter)
		st.node.Available = true
	}

	// 回写分组节点，并让每个 urltest 组选中最优。
	for gi := range a.groups {
		g := &a.groups[gi]
		best := ""
		bestLat := 1 << 30
		for ni := range g.Nodes {
			if st, ok := a.nodeIndex[g.Nodes[ni].ID]; ok {
				g.Nodes[ni].Latency = st.node.Latency
				g.Nodes[ni].Available = st.node.Available
				if g.Type == "urltest" && st.node.Latency < bestLat {
					bestLat = st.node.Latency
					best = st.node.ID
				}
			}
		}
		if g.Type == "urltest" && best != "" {
			g.Selected = best
		}
	}

	// selector 组中的 "auto" 伪节点跟随自动组当前选中的延迟。
	autoLat := 0
	for _, g := range a.groups {
		if g.Type == "urltest" {
			if st, ok := a.nodeIndex[g.Selected]; ok {
				autoLat = st.node.Latency
			}
		}
	}
	for gi := range a.groups {
		g := &a.groups[gi]
		if g.Type != "selector" {
			continue
		}
		for ni := range g.Nodes {
			if g.Nodes[ni].ID == "auto" {
				g.Nodes[ni].Latency = autoLat
			}
		}
	}

	if a.logger != nil {
		a.logger(LogLine{Time: time.Now(), Level: "info", Component: "clash-api", Message: fmt.Sprintf("完成 %d 个节点的延迟测试", len(a.nodeIndex))})
	}
	return len(a.nodeIndex), nil
}

// ListConnections 实现连接查询。
func (a *DevAdapter) ListConnections(ctx context.Context) ([]Connection, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Connection, 0, len(a.conns))
	for _, c := range a.conns {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out, nil
}

// CloseConnection 实现强制断开。
func (a *DevAdapter) CloseConnection(ctx context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.conns[id]
	if !ok {
		return os.ErrNotExist
	}
	delete(a.conns, id)
	if a.logger != nil {
		a.logger(LogLine{Time: time.Now(), Level: "warn", Component: "clash-api", Message: "强制断开连接 " + c.Target})
	}
	return nil
}

// StreamLogs 周期性产生内核日志。
func (a *DevAdapter) StreamLogs(ctx context.Context) (<-chan LogLine, error) {
	ch := make(chan LogLine, 64)
	go func() {
		defer close(ch)
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		seq := 0
		messages := []string{
			"dns: 使用预设 fakeip 解析",
			"router: 匹配规则集 geosite-geolocation-cn",
			"inbound/tun: 保持心跳（开发适配器未启用）",
			"outbound/hk-01: 健康探针 45 ms",
		}
		levels := []string{"info", "debug", "info", "info"}
		components := []string{"dns", "router", "inbound/tun", "outbound"}
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				seq++
				line := LogLine{Time: time.Now(), Level: levels[seq%len(levels)], Component: components[seq%len(components)], Message: messages[seq%len(messages)]}
				select {
				case ch <- line:
				default:
				}
			}
		}
	}()
	return ch, nil
}

// Validate 校验配置能被内核接受（模拟：JSON 结构检查）。
func (a *DevAdapter) Validate(ctx context.Context, content []byte) error {
	var root struct {
		Outbounds []json.RawMessage `json:"outbounds"`
		Inbounds  []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal(content, &root); err != nil {
		return fmt.Errorf("内核 check 失败：%w", err)
	}
	if len(root.Outbounds) == 0 {
		return fmt.Errorf("内核 check 失败：outbounds 不能为空")
	}
	return nil
}

// ApplyRevision 模拟配置发布：短 reload 窗口后成功。
func (a *DevAdapter) ApplyRevision(ctx context.Context, rev Revision) error {
	if err := a.Validate(ctx, rev.Content); err != nil {
		return err
	}
	a.mu.Lock()
	a.startedAt = time.Now()
	a.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(250 * time.Millisecond):
	}
	if a.logger != nil {
		a.logger(LogLine{Time: time.Now(), Level: "info", Component: "control-plane", Message: "已应用配置版本 " + rev.ID})
	}
	return nil
}

// HealthCheck 返回内核健康度。
func (a *DevAdapter) HealthCheck(ctx context.Context) error {
	// 开发适配器：控制 API、默认出站恒定可用，TUN/DNS 报告未启用原因。
	return nil
}

// GetCapabilities 返回开发适配器能力表。
func (a *DevAdapter) GetCapabilities(ctx context.Context) Capabilities {
	return Capabilities{
		CoreVersion: a.core,
		CompileTags: []string{"with_gvisor", "with_quic", "with_dhcp", "with_wireguard"},
		Features: map[string]bool{
			"tun":                  false,
			"clash_api":            true,
			"connection_manager":   true,
			"rule_set_auto_update": true,
			"process_rules":        false,
			"hot_reload":           true,
		},
		FeatureNotices: map[string]string{
			"tun":           "开发适配器阶段不触碰 TUN/路由表；接入真实内核后启用。",
			"process_rules": "实验性特性，需兼容性矩阵验证后开放。",
		},
	}
}

// Restart 模拟内核重启。
func (a *DevAdapter) Restart(ctx context.Context) error {
	a.mu.Lock()
	a.startedAt = time.Now()
	for id := range a.conns {
		delete(a.conns, id)
	}
	a.mu.Unlock()
	if a.logger != nil {
		a.logger(LogLine{Time: time.Now(), Level: "warn", Component: "control-plane", Message: "内核已重启，全部连接被清空"})
	}
	return nil
}
