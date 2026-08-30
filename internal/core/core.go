// Package core 定义代理内核适配层。业务代码只依赖本包的 Adapter 接口，
// 不直接接触 sing-box 的 HTTP 路径或 JSON 结构（实现方案 §5.1）。
package core

import (
	"context"
	"time"
)

// Status 内核运行状态快照，与 Web API 的 /system/status 负载一致。
type Status struct {
	CoreVersion   string    `json:"core_version"`
	Running       bool      `json:"running"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	CurrentProxy  string    `json:"current_proxy"`
	Mode          string    `json:"mode"`
	Traffic       Traffic   `json:"traffic"`
	Resources     Resources `json:"resources"`
}

// Traffic 流量速率与累计值，单位字节。
type Traffic struct {
	UploadRate    float64 `json:"upload_rate"`
	DownloadRate  float64 `json:"download_rate"`
	UploadTotal   int64   `json:"upload_total"`
	DownloadTotal int64   `json:"download_total"`
}

// Resources 控制面资源占用。
type Resources struct {
	MemoryMB   int    `json:"memory_mb"`
	Goroutines int    `json:"goroutines"`
	TUN        string `json:"tun"`
}

// Node 策略组内的单个节点。
type Node struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Region    string `json:"region"`
	Latency   int    `json:"latency"`
	Available bool   `json:"available"`
	SubID     string `json:"subscription_id"` // 归属订阅（识别不出时为空）
}

// Group 策略组：selector / urltest / fallback。
type Group struct {
	Tag      string `json:"tag"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Selected string `json:"selected"`
	Nodes    []Node `json:"nodes"`
}

// Connection 活动连接（默认脱敏展示由 API 层负责）。
type Connection struct {
	ID       string    `json:"id"`
	Source   string    `json:"source"`
	Target   string    `json:"target"`
	Outbound string    `json:"outbound"`
	Rule     string    `json:"rule"`
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
	Started  time.Time `json:"started"`
}

// Capabilities 内核能力表。前端据此隐藏不支持的开关而不是让它们失败。
type Capabilities struct {
	CoreVersion    string            `json:"core_version"`
	CompileTags    []string          `json:"compile_tags"`
	Features       map[string]bool   `json:"features"`
	FeatureNotices map[string]string `json:"feature_notices"`
}

// Revision 提交给内核的一次配置发布。
type Revision struct {
	ID      string
	Content []byte
}

// Adapter 是代理内核的稳定抽象。
type Adapter interface {
	// GetStatus 返回运行状态与流量采样。
	GetStatus(ctx context.Context) (Status, error)
	// ListGroups 返回策略组、节点与当前选择。
	ListGroups(ctx context.Context) ([]Group, error)
	// SelectNode 切换 selector 的选中节点；不触发配置重载。
	SelectNode(ctx context.Context, groupTag, nodeID string) error
	// TestDelay 对全部节点发起延迟测试并更新缓存。
	TestDelay(ctx context.Context) (int, error)
	// ListConnections 返回活动连接。
	ListConnections(ctx context.Context) ([]Connection, error)
	// CloseConnection 强制断开单个连接（危险操作，调用方负责审计）。
	CloseConnection(ctx context.Context, id string) error
	// StreamLogs 把内核日志推送到返回的通道；通道关闭表示停止。
	StreamLogs(ctx context.Context) (<-chan LogLine, error)
	// Validate 校验配置是否可被内核接受。
	Validate(ctx context.Context, content []byte) error
	// ApplyRevision 应用一次配置发布（发送 reload 或重建内核）。
	ApplyRevision(ctx context.Context, rev Revision) error
	// GetCapabilities 返回能力表。
	GetCapabilities(ctx context.Context) Capabilities
	// HealthCheck 探测内核四项健康度：TUN、DNS、控制 API、默认出站。
	HealthCheck(ctx context.Context) error
	// Restart 模拟/触发内核重启。
	Restart(ctx context.Context) error
}

// LogLine 内核侧结构化日志。
type LogLine struct {
	Time      time.Time `json:"time"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
}

// Lifecycle 表示需要显式启动/停止的内核（例如托管 sing-box 子进程）。
// 由 Service.Run 在采样循环前调用 Start，退出时调用 Stop。
type Lifecycle interface {
	// Start 启动内核并等待其控制接口就绪。
	Start(ctx context.Context) error
	// Stop 停止内核并回收进程资源。
	Stop(ctx context.Context) error
}
