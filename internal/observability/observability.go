// Package observability 聚合日志、指标与审计（实现方案 §5.5）。
package observability

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"

	"proxypanel/internal/core"
	"proxypanel/internal/store"
)

// LogEntry 日志条目，JSON 形态与前端 LogEntry 一致。
type LogEntry struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
	Seq       uint64    `json:"seq"` // 单调序号，供 SSE 增量推送
}

// LogBuffer 有界环形日志缓冲；慢消费者丢弃旧 debug 日志而不阻塞。
type LogBuffer struct {
	mu      sync.Mutex
	ring    []LogEntry
	cap     int
	nextSeq uint64
}

// NewLogBuffer 创建容量为 capacity 的缓冲。
func NewLogBuffer(capacity int) *LogBuffer {
	return &LogBuffer{ring: make([]LogEntry, 0, capacity), cap: capacity}
}

// Append 追加日志。
func (b *LogBuffer) Append(level, component, message string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSeq++
	entry := LogEntry{
		ID:        time.Now().Format("20060102150405.000") + "-" + strconv.FormatUint(b.nextSeq, 10),
		Time:      time.Now(),
		Level:     level,
		Component: component,
		Message:   message,
		Seq:       b.nextSeq,
	}
	if len(b.ring) >= b.cap {
		b.ring = b.ring[1:]
	}
	b.ring = append(b.ring, entry)
}

// Since 返回序号大于 sinceSeq 的日志，按时间升序。
func (b *LogBuffer) Since(sinceSeq uint64) []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]LogEntry, 0, 8)
	for _, e := range b.ring {
		if e.Seq > sinceSeq {
			out = append(out, e)
		}
	}
	return out
}

// Clear 清空缓冲（保留单调序号 nextSeq，避免 SSE 增量推送断档后丢失新日志）。
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ring = b.ring[:0]
}

// LatestSeq 返回缓冲中的最大序号（无日志时为 0），供 SSE 增量推送定位起点。
func (b *LogBuffer) LatestSeq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.ring) == 0 {
		return 0
	}
	return b.ring[len(b.ring)-1].Seq
}

// Query 返回按时间倒序的日志，支持组件/内容关键词与等级过滤。
func (b *LogBuffer) Query(keyword, level string, limit int) []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]LogEntry, 0, len(b.ring))
	for i := len(b.ring) - 1; i >= 0 && len(out) < limit; i-- {
		e := b.ring[i]
		if level != "" && e.Level != level {
			continue
		}
		if keyword != "" && !containsFold(e.Component+" "+e.Message, keyword) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func containsFold(haystack, needle string) bool {
	n := len(needle)
	if n == 0 {
		return true
	}
	h := []rune(haystack)
	lo := []rune(needle)
	for i := 0; i+n <= len(h); i++ {
		match := true
		for j := 0; j < n; j++ {
			if lowerRune(h[i+j]) != lowerRune(lo[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func lowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}

// MetricPoint 流量历史点。
type MetricPoint struct {
	Time        string  `json:"time"`
	Upload      float64 `json:"upload"`
	Download    float64 `json:"download"`
	UploadSum   int64   `json:"-"`
	DownloadSum int64   `json:"-"`
}

// Collector 周期采样内核状态，维护历史窗口并转发内核日志。
type Collector struct {
	adapter     core.Adapter
	logs        *LogBuffer
	store       *store.Root
	mu          sync.Mutex
	history     []MetricPoint
	lastPersist time.Time
	persistedUp int64
	persistedDl int64
}

// NewCollector 创建采样器。
func NewCollector(adapter core.Adapter, logs *LogBuffer, st *store.Root) *Collector {
	return &Collector{adapter: adapter, logs: logs, store: st}
}

// Logs 暴露日志缓冲。
func (c *Collector) Logs() *LogBuffer { return c.logs }

// History 返回最近 limit 个流量点（按时间正序）。
func (c *Collector) History(limit int) []MetricPoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 || limit > len(c.history) {
		limit = len(c.history)
	}
	out := make([]MetricPoint, limit)
	copy(out, c.history[len(c.history)-limit:])
	return out
}

// Start 启动内核日志转发；随 ctx 结束。
func (c *Collector) Start(ctx context.Context) {
	if stream, err := c.adapter.StreamLogs(ctx); err == nil {
		go func() {
			for line := range stream {
				c.logs.Append(line.Level, line.Component, line.Message)
			}
		}()
	}
}

// Observe 记录一次状态采样（由 Service 的 1 秒循环调用）。
func (c *Collector) Observe(status core.Status) {
	point := MetricPoint{
		Time:     time.Now().Format(time.RFC3339),
		Upload:   status.Traffic.UploadRate,
		Download: status.Traffic.DownloadRate,
	}
	c.mu.Lock()
	c.history = append(c.history, point)
	if len(c.history) > 600 {
		c.history = c.history[len(c.history)-600:]
	}
	c.mu.Unlock()

	// 每 5 分钟落库一次累计流量增量（实现方案 §5.5）。
	if time.Since(c.lastPersist) >= 5*time.Minute {
		c.lastPersist = time.Now()
		_ = c.store.SaveJSON("runtime/traffic_totals.json", map[string]any{
			"upload_total":   status.Traffic.UploadTotal,
			"download_total": status.Traffic.DownloadTotal,
			"saved_at":       time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// Audit 记录审计事件（实现方案 §7）。
func (c *Collector) Audit(actor, ip, action, target, result, traceID string) {
	_ = c.store.AppendAudit(store.AuditEvent{
		Time: time.Now().UTC(), Actor: actor, IP: ip,
		Action: action, Target: target, Result: result, TraceID: traceID,
	})
}

// SortLogEntries 按时间倒序排列（供需要稳定顺序的调用方使用）。
func SortLogEntries(entries []LogEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Time.After(entries[j].Time) })
}
