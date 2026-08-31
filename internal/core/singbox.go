package core

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SingBoxOptions 配置真实内核适配器（实现方案 §5.1、§2.1）。
type SingBoxOptions struct {
	Binary     string // sing-box 二进制路径，默认 "sing-box"
	ConfigPath string // 运行配置 JSON 路径（默认由 app 注入 runtime/config.json）
	WorkDir    string // 子进程工作目录（相对路径规则集以此为根）
	Controller string // Clash API 监听地址 "127.0.0.1:PORT"，留空自动分配随机高端口
	Secret     string // Clash API 密钥，留空自动生成
	TestURL    string // 测速 URL，默认 gstatic generate_204
	External   bool   // 不托管子进程，仅通过 PIDFile 发送 SIGHUP
	PIDFile    string // External 模式下读取内核 PID 用于 reload
}

// clashProxy 是 Clash API `/proxies` 返回的单个出站/策略组。
type clashProxy struct {
	Type    string   `json:"type"`
	Now     string   `json:"now"`
	All     []string `json:"all"`
	History []struct {
		Time  string `json:"time"`
		Delay int    `json:"delay"`
	} `json:"history"`
}

// SingBoxAdapter 通过 Clash API + 受控信号驱动真实的 sing-box 内核。
// 满足 Adapter 与 Lifecycle 两个接口。
type SingBoxAdapter struct {
	opts   SingBoxOptions
	logger func(LogLine)

	controller string // 解析后的 Controller
	secret     string

	mu        sync.Mutex
	client    *http.Client
	proc      *exec.Cmd
	cancel    context.CancelFunc
	done      chan struct{}
	running   bool
	startedAt time.Time

	version     string
	compileTags []string

	// 流量：/traffic 是每秒快照的流式端点，由常驻 goroutine 累加（实现方案 §5.5）。
	trafficMu     sync.Mutex
	trafficUp     int64
	trafficDown   int64
	trafficWindow []trafficSample
	trafficClient *http.Client
	trafficCancel context.CancelFunc

	delayMu     sync.Mutex
	delays      map[string]int
	unavailable map[string]bool

	nodeResolver func(tag string) (name, subID string)
}

// trafficSample 是 /traffic 流的一行：上一秒的字节增量。
type trafficSample struct {
	at   time.Time
	up   int64
	down int64
}

// SetNodeResolver 注入节点 tag → (显示名称, 归属订阅) 的映射（订阅模块提供）。
func (a *SingBoxAdapter) SetNodeResolver(fn func(tag string) (name, subID string)) {
	a.nodeResolver = fn
}

func (a *SingBoxAdapter) nodeMeta(tag string) (name, subID string) {
	if a.nodeResolver != nil {
		if n, s := a.nodeResolver(tag); n != "" {
			return n, s
		}
	}
	return tag, ""
}

func (a *SingBoxAdapter) displayName(tag string) string {
	name, _ := a.nodeMeta(tag)
	return name
}

// NewSingBoxAdapter 构造真实内核适配器并做一次轻量能力探测。
func NewSingBoxAdapter(opts SingBoxOptions) *SingBoxAdapter {
	if opts.Binary == "" {
		opts.Binary = "sing-box"
	}
	if opts.TestURL == "" {
		opts.TestURL = "https://www.gstatic.com/generate_204"
	}
	a := &SingBoxAdapter{
		opts:     opts,
		client:   &http.Client{Timeout: 5 * time.Second},
		delays:   map[string]int{},
		unavailable: map[string]bool{},
	}
	// 流量流需要长连接：不能用带总超时的 client。
	a.trafficClient = &http.Client{Timeout: 0}
	a.resolveController()
	a.detectCore()
	return a
}

// SetLogger 注册内核日志回调。
func (a *SingBoxAdapter) SetLogger(fn func(LogLine)) { a.logger = fn }

// resolveController 解析控制面监听地址与密钥；自动生成的值持久化，保证重启一致。
func (a *SingBoxAdapter) resolveController() {
	persisted := a.loadSecrets()

	if a.opts.Controller != "" {
		a.controller = a.opts.Controller
	} else if persisted != nil && persisted.Controller != "" {
		a.controller = persisted.Controller
	} else if port, err := freePort(); err == nil {
		a.controller = net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	} else {
		a.controller = "127.0.0.1:9095"
	}

	if a.opts.Secret != "" {
		a.secret = a.opts.Secret
	} else if persisted != nil && persisted.Secret != "" {
		a.secret = persisted.Secret
	} else {
		a.secret = randomToken(16)
	}

	if persisted == nil || persisted.Controller != a.controller || persisted.Secret != a.secret {
		a.persistSecrets()
	}
}

type coreSecrets struct {
	Controller string `json:"controller"`
	Secret     string `json:"secret"`
}

func (a *SingBoxAdapter) secretsPath() string {
	return filepath.Join(a.opts.WorkDir, "core_secrets.json")
}

func (a *SingBoxAdapter) loadSecrets() *coreSecrets {
	if a.opts.WorkDir == "" {
		return nil
	}
	data, err := os.ReadFile(a.secretsPath())
	if err != nil {
		return nil
	}
	var s coreSecrets
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	return &s
}

func (a *SingBoxAdapter) persistSecrets() {
	if a.opts.WorkDir == "" {
		return
	}
	data, _ := json.Marshal(coreSecrets{Controller: a.controller, Secret: a.secret})
	_ = atomicWriteFile(a.secretsPath(), data)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func (a *SingBoxAdapter) detectCore() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a.opts.Binary, "version").CombinedOutput()
	if err != nil {
		a.version = "sing-box (未找到二进制)"
		return
	}
	var v struct {
		Version string   `json:"version"`
		Tags    []string `json:"tags"`
	}
	if json.Unmarshal(out, &v) == nil && v.Version != "" {
		a.version = v.Version
		a.compileTags = v.Tags
	} else {
		// 非 JSON 输出：只保留首行，避免冗长信息撑爆界面。
		if line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n"); line != "" {
			a.version = line
		} else {
			a.version = "sing-box (未知版本)"
		}
	}
}

// ---------- Lifecycle ----------

// Start 启动内核并等待 Clash API 就绪。
func (a *SingBoxAdapter) Start(ctx context.Context) error {
	if a.opts.External {
		return a.startExternal()
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil
	}
	if _, err := os.Stat(a.opts.Binary); err != nil {
		a.mu.Unlock()
		return fmt.Errorf("找不到内核二进制 %q（请先安装 sing-box 或用 --sing-box-bin 指定）：%w", a.opts.Binary, err)
	}
	if a.opts.ConfigPath == "" {
		a.mu.Unlock()
		return fmt.Errorf("未指定内核配置路径 ConfigPath")
	}

	runCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(runCtx, a.opts.Binary, "run", "-c", a.opts.ConfigPath)
	if a.opts.WorkDir != "" {
		cmd.Dir = a.opts.WorkDir
	}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		a.mu.Unlock()
		cancel()
		return fmt.Errorf("启动内核失败：%w", err)
	}
	a.proc = cmd
	a.cancel = cancel
	a.done = make(chan struct{})
	a.running = true
	a.startedAt = time.Now()
	a.mu.Unlock()

	go a.pipeLogs(stdout)
	go a.pipeLogs(stderr)
	go a.monitor(cmd)
	a.startTrafficStream()

	// 等待控制接口就绪（最多 5 秒）。
	if err := a.waitReady(ctx); err != nil {
		a.emit("warn", "core", "内核已启动但控制接口尚未就绪："+err.Error())
	}
	a.emit("info", "core", "内核已启动，Clash API 监听 "+a.controller)
	return nil
}

// startTrafficStream 启动 /traffic 常驻消费者（幂等）。
func (a *SingBoxAdapter) startTrafficStream() {
	a.mu.Lock()
	if a.trafficCancel != nil {
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.trafficCancel = cancel
	a.mu.Unlock()
	go a.trafficLoop(ctx)
}

func (a *SingBoxAdapter) startExternal() error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = true
	a.startedAt = time.Now()
	a.mu.Unlock()
	a.emit("info", "core", "外部内核模式：Clash API "+a.controller)
	a.startTrafficStream()
	return nil
}

func (a *SingBoxAdapter) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !a.isRunning() {
			return fmt.Errorf("内核进程已退出")
		}
		if a.reachVersion() {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("超时")
}

func (a *SingBoxAdapter) monitor(cmd *exec.Cmd) {
	err := cmd.Wait()
	a.mu.Lock()
	a.running = false
	a.proc = nil
	close(a.done)
	a.mu.Unlock()
	a.stopTrafficStream()
	if err != nil {
		a.emit("error", "core", "内核进程退出："+err.Error())
	}
}

// Stop 停止内核。
func (a *SingBoxAdapter) Stop(ctx context.Context) error {
	a.stopTrafficStream()
	if a.opts.External {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return nil
	}
	a.mu.Lock()
	if !a.running || a.proc == nil || a.proc.Process == nil {
		a.mu.Unlock()
		return nil
	}
	proc := a.proc
	cancel := a.cancel
	done := a.done
	a.mu.Unlock()

	_ = proc.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		_ = proc.Process.Kill()
	}
	if cancel != nil {
		cancel()
	}
	return nil
}

// stopTrafficStream 结束 /traffic 消费者并允许后续重新启动。
func (a *SingBoxAdapter) stopTrafficStream() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.trafficCancel != nil {
		a.trafficCancel()
		a.trafficCancel = nil
	}
}

// trafficLoop 维持 /traffic 流连接，断线自动重连。
func (a *SingBoxAdapter) trafficLoop(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := a.consumeTrafficStream(ctx); err != nil && ctx.Err() == nil {
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		backoff = time.Second
		time.Sleep(200 * time.Millisecond) // 流正常结束（如内核重载）后快速重连
	}
}

// consumeTrafficStream 读取 /traffic 流：每秒一行 JSON 快照（上一秒增量），累加到累计值与滑动窗口。
func (a *SingBoxAdapter) consumeTrafficStream(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+a.controller+"/traffic", nil)
	if err != nil {
		return err
	}
	if a.secret != "" {
		req.Header.Set("Authorization", "Bearer "+a.secret)
	}
	resp, err := a.trafficClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("内核 API /traffic 返回 %d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), 16*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var snapshot struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		}
		if json.Unmarshal([]byte(line), &snapshot) != nil {
			continue
		}
		a.trafficMu.Lock()
		a.trafficUp += snapshot.Up
		a.trafficDown += snapshot.Down
		a.trafficWindow = append(a.trafficWindow, trafficSample{
			at: time.Now(), up: snapshot.Up, down: snapshot.Down,
		})
		const window = 12 // 保留最近 12 秒样本计算速率
		if len(a.trafficWindow) > window {
			a.trafficWindow = a.trafficWindow[len(a.trafficWindow)-window:]
		}
		a.trafficMu.Unlock()
	}
	return scanner.Err()
}

// trafficTotals 返回累计流量与当前速率（锁定调用）。
func (a *SingBoxAdapter) trafficTotals() (up, down int64, upRate, downRate float64) {
	a.trafficMu.Lock()
	defer a.trafficMu.Unlock()
	up, down = a.trafficUp, a.trafficDown
	if len(a.trafficWindow) >= 2 {
		if span := a.trafficWindow[len(a.trafficWindow)-1].at.Sub(a.trafficWindow[0].at).Seconds(); span > 0 {
			var wu, wd int64
			for _, s := range a.trafficWindow {
				wu += s.up
				wd += s.down
			}
			upRate, downRate = float64(wu)/span, float64(wd)/span
		}
	}
	return up, down, upRate, downRate
}

func (a *SingBoxAdapter) emit(level, component, message string) {
	if a.logger == nil {
		return
	}
	a.logger(LogLine{Time: time.Now(), Level: level, Component: component, Message: message})
}

// pipeLogs 逐行读取内核标准输出/错误并转发到日志缓冲。
func (a *SingBoxAdapter) pipeLogs(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if parsed, err := parseSingBoxLog([]byte(line)); err == nil {
			a.emit(parsed.Level, "sing-box", parsed.Message)
		} else {
			a.emit(classifyLevel(line), "sing-box", line)
		}
	}
}

func classifyLevel(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "level=error") || strings.Contains(l, " error "):
		return "error"
	case strings.Contains(l, "level=warn") || strings.Contains(l, " warn "):
		return "warn"
	default:
		return "info"
	}
}

// parseSingBoxLog 解析 sing-box 结构化/半结构化日志行。
func parseSingBoxLog(data []byte) (LogLine, error) {
	var raw struct {
		Time    string `json:"time"`
		Level   string `json:"level"`
		Msg     string `json:"msg"`
		Message string `json:"message"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return LogLine{}, err
	}
	msg := raw.Message
	if msg == "" {
		msg = raw.Msg
	}
	if raw.Payload != "" {
		var p struct {
			Level   string `json:"level"`
			Msg     string `json:"msg"`
			Message string `json:"message"`
		}
		if json.Unmarshal([]byte(raw.Payload), &p) == nil {
			if p.Level != "" {
				raw.Level = p.Level
			}
			if p.Msg != "" {
				msg = p.Msg
			} else if p.Message != "" {
				msg = p.Message
			}
		} else {
			msg = raw.Payload
		}
	}
	level := raw.Level
	if level == "" {
		level = "info"
	}
	t := time.Now()
	if raw.Time != "" {
		if parsed, err := time.Parse(time.RFC3339, raw.Time); err == nil {
			t = parsed
		}
	}
	return LogLine{Time: t, Level: level, Component: "sing-box", Message: msg}, nil
}

// ---------- 状态 ----------

// GetStatus 返回内核状态与流量采样。
func (a *SingBoxAdapter) GetStatus(ctx context.Context) (Status, error) {
	status := Status{
		CoreVersion: a.version,
		Running:     a.isRunning(),
		StartedAt:   a.startedAt,
		Mode:        "rule",
	}
	if status.Running {
		status.UptimeSeconds = int64(time.Since(a.startedAt).Seconds())
	}

	up, down, upRate, downRate := a.trafficTotals()
	status.Traffic.UploadTotal = up
	status.Traffic.DownloadTotal = down
	status.Traffic.UploadRate = upRate
	status.Traffic.DownloadRate = downRate

	if groups, err := a.ListGroups(ctx); err == nil {
		status.CurrentProxy = a.currentSelector(groups)
	}
	status.Resources = a.resources()
	return status, nil
}

func (a *SingBoxAdapter) isRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.opts.External {
		return a.running
	}
	// 外部模式：以 PID 存活作为运行判定。
	if a.opts.PIDFile == "" {
		return a.running
	}
	data, err := os.ReadFile(a.opts.PIDFile)
	if err != nil {
		return false
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil || pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func (a *SingBoxAdapter) resources() Resources {
	res := Resources{}
	res.TUN = "未启用"
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		res.TUN = "可用"
	}
	a.mu.Lock()
	proc := a.proc
	a.mu.Unlock()
	if proc != nil && proc.Process != nil && !a.opts.External {
		res.MemoryMB, res.Goroutines = readProcStats(proc.Process.Pid)
	}
	return res
}

func readProcStats(pid int) (memMB, threads int) {
	// Linux: 读取 /proc/{pid}/status
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(line, "VmRSS:"):
				var kb int
				if _, err := fmt.Sscanf(line, "VmRSS: %d kB", &kb); err == nil {
					memMB = kb / 1024
				}
			case strings.HasPrefix(line, "Threads:"):
				fmt.Sscanf(line, "Threads: %d", &threads)
			}
		}
		return memMB, threads
	}
	// macOS / BSD 回退：macOS 的 ps 不支持 nlwp，内存取 rss=，线程数用 ps -M 行数。
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-o", "rss=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err == nil {
		var rss int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &rss); err == nil {
			memMB = rss / 1024
		}
	}
	threadCtx, threadCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer threadCancel()
	tout, terr := exec.CommandContext(threadCtx, "ps", "-M", "-p", fmt.Sprintf("%d", pid)).Output()
	if terr == nil {
		lines := strings.Split(strings.TrimSpace(string(tout)), "\n")
		if len(lines) > 1 {
			threads = len(lines) - 1 // 去掉标题行
		}
	}
	if memMB == 0 && threads == 0 && err != nil && terr != nil {
		return 0, 0
	}
	return memMB, threads
}

func (a *SingBoxAdapter) reachVersion() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	var v map[string]any
	return a.getJSON(ctx, "/version", &v) == nil
}

// ---------- HTTP 客户端 ----------

func (a *SingBoxAdapter) getJSON(ctx context.Context, path string, target any) error {
	body, status, err := a.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("内核 API %s 返回 %d", path, status)
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, target)
}

func (a *SingBoxAdapter) request(ctx context.Context, method, path string, payload []byte) ([]byte, int, error) {
	endpoint := "http://" + a.controller + path
	var reader io.Reader
	if payload != nil {
		reader = strings.NewReader(string(payload))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, 0, err
	}
	if a.secret != "" {
		req.Header.Set("Authorization", "Bearer "+a.secret)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// ---------- 策略组与节点 ----------

// ListGroups 返回策略组、节点与当前选择（单次 `/proxies` 调用）。
func (a *SingBoxAdapter) ListGroups(ctx context.Context) ([]Group, error) {
	var wrapper struct {
		Proxies map[string]clashProxy `json:"proxies"`
	}
	if err := a.getJSON(ctx, "/proxies", &wrapper); err != nil {
		return nil, err
	}
	proxies := wrapper.Proxies
	if proxies == nil {
		return nil, nil
	}
	var groups []Group
	groups = make([]Group, 0, len(proxies))
	for tag, p := range proxies {
		if !isGroupType(p.Type) {
			continue
		}
		// sing-box 的 GLOBAL 是特殊组（Fallback），不支持通过 Clash API 切换，跳过。
		if tag == "GLOBAL" {
			continue
		}
		nodes := make([]Node, 0, len(p.All))
		for _, member := range p.All {
			latency := a.cachedDelay(member)
			if latency == 0 {
				// 内核 urltest 持续测速的历史记录作为回退。
				if h := proxies[member].History; len(h) > 0 {
					latency = h[len(h)-1].Delay
				}
			}
			name, subID := a.nodeMeta(member)
			nodes = append(nodes, Node{
				ID:        member,
				Name:      name,
				Protocol:  clashTypeToProtocol(proxies[member].Type),
				Region:    guessRegion(name),
				Latency:   latency,
				Available: a.isAvailable(member),
				SubID:     subID,
			})
		}
		groups = append(groups, Group{
			Tag: tag, Name: a.displayName(tag), Type: groupKind(p.Type),
			Selected: p.Now, Nodes: nodes,
		})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Tag < groups[j].Tag })
	return groups, nil
}

// SelectNode 切换 selector 选中节点（内核 API 直接生效，不触发重载）。
func (a *SingBoxAdapter) SelectNode(ctx context.Context, groupTag, nodeID string) error {
	payload, _ := json.Marshal(map[string]string{"name": nodeID})
	body, status, err := a.request(ctx, http.MethodPut, "/proxies/"+url.PathEscape(groupTag), payload)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("切换节点失败（%d）：%s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

// SetMode 切换代理模式（rule/global/direct），通过 Clash API 直接生效，不触发内核重启。
func (a *SingBoxAdapter) SetMode(ctx context.Context, mode string) error {
	payload, _ := json.Marshal(map[string]string{"mode": mode})
	body, status, err := a.request(ctx, http.MethodPatch, "/configs", payload)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("切换模式失败（%d）：%s", status, strings.TrimSpace(string(body)))
	}
	a.emit("info", "core", "代理模式已切换为 "+mode)
	return nil
}

// TestDelay 对全部策略组节点发起延迟测试并缓存结果，返回测试节点数。
func (a *SingBoxAdapter) TestDelay(ctx context.Context) (int, error) {
	groups, err := a.ListGroups(ctx)
	if err != nil {
		return 0, err
	}
	tested := 0
	seen := map[string]bool{}
	for _, g := range groups {
		for _, node := range g.Nodes {
			if isGroupProtocol(node.Protocol) || seen[node.ID] {
				continue
			}
			seen[node.ID] = true
			pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			delay, err := a.delay(pctx, node.ID)
			cancel()
			if err != nil {
				a.setUnavailable(node.ID, true)
				continue
			}
			a.setDelay(node.ID, delay)
			tested++
		}
	}
	return tested, nil
}

func (a *SingBoxAdapter) delay(ctx context.Context, name string) (int, error) {
	path := fmt.Sprintf("/proxies/%s/delay?url=%s&timeout=5000", url.PathEscape(name), url.QueryEscape(a.opts.TestURL))
	var body struct {
		Delay int `json:"delay"`
	}
	if err := a.getJSON(ctx, path, &body); err != nil {
		return 0, err
	}
	if body.Delay <= 0 {
		return 0, fmt.Errorf("无效延迟")
	}
	a.setDelay(name, body.Delay)
	return body.Delay, nil
}

func (a *SingBoxAdapter) cachedDelay(name string) int {
	a.delayMu.Lock()
	defer a.delayMu.Unlock()
	return a.delays[name]
}

func (a *SingBoxAdapter) setDelay(name string, ms int) {
	a.delayMu.Lock()
	defer a.delayMu.Unlock()
	a.delays[name] = ms
	delete(a.unavailable, name)
}

func (a *SingBoxAdapter) setUnavailable(name string, u bool) {
	a.delayMu.Lock()
	defer a.delayMu.Unlock()
	if u {
		a.unavailable[name] = true
		delete(a.delays, name)
	} else {
		delete(a.unavailable, name)
	}
}

func (a *SingBoxAdapter) isAvailable(name string) bool {
	a.delayMu.Lock()
	defer a.delayMu.Unlock()
	return !a.unavailable[name]
}

// currentSelector 返回当前生效的出口（显示名）。
func (a *SingBoxAdapter) currentSelector(groups []Group) string {
	// urltest 组自动选中的实际节点。
	autoPick := ""
	for _, g := range groups {
		if g.Type == "urltest" && g.Selected != "" {
			autoPick = g.Selected
		}
	}
	for _, g := range groups {
		if g.Type != "selector" || g.Selected == "" {
			continue
		}
		// 选中项是 auto：展开到 urltest 实际节点。
		if g.Selected == "auto" {
			if autoPick != "" {
				return a.displayName(autoPick)
			}
			return "auto"
		}
		return a.displayName(g.Selected)
	}
	return "direct"
}

// ---------- 连接 ----------

// ListConnections 返回活动连接。
func (a *SingBoxAdapter) ListConnections(ctx context.Context) ([]Connection, error) {
	var doc struct {
		Connections []struct {
			ID       string `json:"id"`
			Metadata struct {
				SourceIP        string `json:"sourceIP"`
				SourcePort      string `json:"sourcePort"`
				DestinationIP   string `json:"destinationIP"`
				DestinationPort string `json:"destinationPort"`
				Host            string `json:"host"`
			} `json:"metadata"`
			Upload   int64    `json:"upload"`
			Download int64    `json:"download"`
			Start    string   `json:"start"`
			Chains   []string `json:"chains"`
			Rule     string   `json:"rule"`
		} `json:"connections"`
	}
	if err := a.getJSON(ctx, "/connections", &doc); err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(doc.Connections))
	for _, c := range doc.Connections {
		target := c.Metadata.Host
		if target == "" {
			target = c.Metadata.DestinationIP
		}
		if c.Metadata.DestinationPort != "" {
			target = net.JoinHostPort(target, c.Metadata.DestinationPort)
		}
		source := net.JoinHostPort(c.Metadata.SourceIP, c.Metadata.SourcePort)
		outbound := ""
		if len(c.Chains) > 0 {
			outbound = c.Chains[len(c.Chains)-1]
		}
		start, _ := time.Parse(time.RFC3339, c.Start)
		out = append(out, Connection{
			ID: c.ID, Source: source, Target: target,
			Outbound: outbound, Rule: c.Rule,
			Upload: c.Upload, Download: c.Download, Started: start,
		})
	}
	return out, nil
}

// CloseConnection 强制断开连接。
func (a *SingBoxAdapter) CloseConnection(ctx context.Context, id string) error {
	body, status, err := a.request(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("断开连接失败（%d）：%s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

// ---------- 日志 ----------

// StreamLogs 通过 WebSocket 订阅内核日志流。
func (a *SingBoxAdapter) StreamLogs(ctx context.Context) (<-chan LogLine, error) {
	ws, err := dialLogWS(ctx, a.controller, a.secret)
	if err != nil {
		return nil, err
	}
	ch := make(chan LogLine, 64)
	go func() {
		defer close(ch)
		defer ws.close()
		go func() {
			<-ctx.Done()
			ws.close()
		}()
		for {
			payload, err := ws.readFrame()
			if err != nil {
				return
			}
			line, parseErr := parseSingBoxLog(payload)
			if parseErr != nil {
				line = LogLine{Time: time.Now(), Level: "info", Component: "sing-box", Message: string(payload)}
			}
			select {
			case ch <- line:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// ---------- 校验与发布 ----------

// Validate 使用 sing-box check 校验候选配置（先注入 Clash API 段）。
func (a *SingBoxAdapter) Validate(ctx context.Context, content []byte) error {
	return a.check(ctx, a.injectClashAPI(content))
}

// ApplyRevision 原子替换运行配置。sing-box 的 SIGHUP 只重载外部资源（规则集/地理数据），
// 主配置变更（模式、入站、路由等）必须重启内核进程才会生效。
func (a *SingBoxAdapter) ApplyRevision(ctx context.Context, rev Revision) error {
	final := a.injectClashAPI(rev.Content)
	if err := a.check(ctx, final); err != nil {
		return fmt.Errorf("内核 check 失败：%w", err)
	}
	if a.opts.ConfigPath == "" {
		return fmt.Errorf("未指定内核配置路径")
	}
	if err := atomicWriteFile(a.opts.ConfigPath, final); err != nil {
		return err
	}

	a.mu.Lock()
	running := a.running
	proc := a.proc
	a.mu.Unlock()

	if a.opts.External {
		return a.signalExternal(syscall.SIGHUP)
	}
	if !running || proc == nil || proc.Process == nil {
		// 尚未启动：配置已暂存，Start 时以最新配置启动。
		return nil
	}

	restartCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := a.Stop(restartCtx); err != nil {
		return fmt.Errorf("停止旧内核实例失败：%w", err)
	}
	if err := a.Start(restartCtx); err != nil {
		return fmt.Errorf("重启内核失败：%w", err)
	}
	a.emit("info", "core", "内核已重启，应用配置版本 "+rev.ID)
	return nil
}

func (a *SingBoxAdapter) signalExternal(sig syscall.Signal) error {
	if a.opts.PIDFile == "" {
		return nil
	}
	data, err := os.ReadFile(a.opts.PIDFile)
	if err != nil {
		return fmt.Errorf("读取 PID 文件失败：%w", err)
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil {
		return fmt.Errorf("PID 文件格式无效：%w", err)
	}
	if err := syscall.Kill(pid, sig); err != nil {
		return fmt.Errorf("向 PID %d 发送 SIGHUP 失败：%w", pid, err)
	}
	return nil
}

// check 用固定二进制执行 sing-box check。
func (a *SingBoxAdapter) check(ctx context.Context, content []byte) error {
	tmp, err := os.CreateTemp("", "sp-check-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	cmd := exec.CommandContext(ctx, a.opts.Binary, "check", "-c", tmpName)
	if a.opts.WorkDir != "" {
		cmd.Dir = a.opts.WorkDir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// injectClashAPI 覆写 config 的 experimental.clash_api，使其与适配器一致。
// 保留原有 default_mode（若存在），否则回落 rule。
func (a *SingBoxAdapter) injectClashAPI(content []byte) []byte {
	var root map[string]any
	if json.Unmarshal(content, &root) != nil {
		return content
	}
	exp, _ := root["experimental"].(map[string]any)
	if exp == nil {
		exp = map[string]any{}
	}
	// 保留原有 default_mode，不硬编码覆盖。
	mode := "rule"
	if prev, _ := exp["clash_api"].(map[string]any); prev != nil {
		if dm, ok := prev["default_mode"].(string); ok && dm != "" {
			mode = dm
		}
	}
	exp["clash_api"] = map[string]any{
		"external_controller": a.controller,
		"secret":              a.secret,
		"default_mode":        mode,
	}
	root["experimental"] = exp
	out, err := json.Marshal(root)
	if err != nil {
		return content
	}
	return out
}

// ---------- 能力与健康 ----------

// GetCapabilities 返回内核能力表。
func (a *SingBoxAdapter) GetCapabilities(ctx context.Context) Capabilities {
	hasTag := func(t string) bool {
		for _, tag := range a.compileTags {
			if tag == t {
				return true
			}
		}
		return false
	}
	tun := hasTag("with_gvisor") || hasTag("with_tun") || hasTag("with_stack")
	caps := Capabilities{
		CoreVersion: a.version,
		CompileTags: a.compileTags,
		Features: map[string]bool{
			"clash_api":            true,
			"tun":                  tun,
			"connection_manager":   true,
			"rule_set_auto_update": true,
			"process_rules":        hasTag("with_clash_api"),
			"hot_reload":           true,
		},
		FeatureNotices: map[string]string{
			"tun":           tunNotice(tun),
			"process_rules": "进程规则为实验性特性，需兼容性矩阵验证后开放。",
		},
	}
	return caps
}

// HealthCheck 探测内核健康度：进程存活 + 控制接口可达。
func (a *SingBoxAdapter) HealthCheck(ctx context.Context) error {
	if !a.isRunning() {
		return nil // 尚未启动，后续 Run 会启动
	}
	if !a.reachVersion() {
		return fmt.Errorf("内核控制接口不可达")
	}
	return nil
}

// Restart 触发内核完整重启（Stop + Start）。
func (a *SingBoxAdapter) Restart(ctx context.Context) error {
	if a.opts.External {
		return a.signalExternal(syscall.SIGHUP)
	}
	stopCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := a.Stop(stopCtx); err != nil {
		return err
	}
	startCtx, startCancel := context.WithTimeout(ctx, 10*time.Second)
	defer startCancel()
	return a.Start(startCtx)
}

// ---------- 工具 ----------

func isGroupType(t string) bool {
	switch strings.ToLower(t) {
	case "selector", "urltest", "fallback", "loadbalance":
		return true
	default:
		return false
	}
}

func groupKind(t string) string {
	switch strings.ToLower(t) {
	case "selector":
		return "selector"
	case "urltest":
		return "urltest"
	case "fallback":
		return "fallback"
	case "loadbalance":
		return "loadbalance"
	default:
		return strings.ToLower(t)
	}
}

func clashTypeToProtocol(t string) string {
	switch strings.ToLower(t) {
	case "selector":
		return "selector"
	case "urltest":
		return "urltest"
	case "fallback":
		return "fallback"
	case "loadbalance":
		return "loadbalance"
	case "trojan":
		return "trojan"
	case "vless":
		return "vless"
	case "vmess":
		return "vmess"
	case "shadowsocks":
		return "ss"
	case "hysteria2":
		return "hysteria2"
	case "tuic":
		return "tuic"
	case "http":
		return "http"
	case "socks":
		return "socks"
	case "direct", "block", "dns":
		return strings.ToLower(t)
	default:
		return strings.ToLower(t)
	}
}

func isGroupProtocol(p string) bool {
	switch p {
	case "selector", "urltest", "fallback", "loadbalance":
		return true
	default:
		return false
	}
}

// guessRegion 依据 tag 做轻量地区猜测（与订阅模块的脱敏展示保持一致风格）。
func guessRegion(tag string) string {
	lower := strings.ToLower(tag)
	switch {
	case strings.Contains(lower, "hk") || strings.Contains(tag, "香港"):
		return "香港"
	case strings.Contains(lower, "jp") || strings.Contains(tag, "日本"):
		return "日本"
	case strings.Contains(lower, "sg") || strings.Contains(tag, "新加坡"):
		return "新加坡"
	case strings.Contains(lower, "tw") || strings.Contains(tag, "台湾"):
		return "台湾"
	case strings.Contains(lower, "us") || strings.Contains(tag, "美国"):
		return "美国"
	default:
		return "节点"
	}
}

func tunNotice(tun bool) string {
	if tun {
		return "已检测到 TUN 能力。"
	}
	return "内核二进制未编译 TUN 栈（with_gvisor/with_tun），或运行环境缺少 /dev/net/tun。"
}

func randomToken(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".core-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
