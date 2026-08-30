// Package app 是控制面的组装根：装配存储、适配器、领域管理器与 API，
// 并通过 go:embed 携带 Web 静态资源。
package app

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"proxypanel/internal/api"
	"proxypanel/internal/config"
	"proxypanel/internal/core"
	"proxypanel/internal/observability"
	"proxypanel/internal/ruleset"
	"proxypanel/internal/store"
	"proxypanel/internal/subscription"
)

//go:embed static
var staticFS embed.FS

// Config 服务启动参数。
type Config struct {
	Secret  string
	DataDir string
	Version string

	// ResetSecret 为 true 时忽略已保存的密钥，重新生成并在控制台显示一次。
	ResetSecret bool

	// UseSingBox 为 true 时使用真实内核适配器，否则使用开发适配器。
	UseSingBox bool
	SingBox    core.SingBoxOptions
}

// Service 控制面服务。
type Service struct {
	version    string
	logger     *slog.Logger
	adapter    core.Adapter
	root       *store.Root
	keys       *store.Keyring
	collect    *observability.Collector
	cfgs       *config.Manager
	subs       *subscription.Manager
	ruleSets   *ruleset.Manager
	server     *api.Server
	secretOnce string // 仅首次初始化生成时非空

	useSingBox bool
	singBox    core.SingBoxOptions

	mu       sync.Mutex
	settings store.Settings

	// dueMu/dueAttempt 记录每个订阅最近一次定时尝试时间（含失败），
	// 失败时 LastUpdated 不前进，避免每分钟重试轰炸订阅服务器。
	dueMu      sync.Mutex
	dueAttempt map[string]time.Time
}

// bufferHandler 将 slog 记录同步写入日志缓冲（同时保留原有控制台输出），
// 使「订阅更新失败」等控制台日志出现在面板日志页。
type bufferHandler struct {
	inner  slog.Handler
	buffer *observability.LogBuffer
}

func (h *bufferHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *bufferHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.buffer != nil {
		msg := r.Message
		r.Attrs(func(a slog.Attr) bool {
			msg += " " + a.Key + "=" + a.Value.String()
			return true
		})
		h.buffer.Append(logLevelString(r.Level), "panel", msg)
	}
	return h.inner.Handle(ctx, r)
}

func (h *bufferHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &bufferHandler{inner: h.inner.WithAttrs(attrs), buffer: h.buffer}
}

func (h *bufferHandler) WithGroup(name string) slog.Handler {
	return &bufferHandler{inner: h.inner.WithGroup(name), buffer: h.buffer}
}

func logLevelString(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

// NewService 装配全部组件并完成首次初始化（种子配置）。
func NewService(cfg Config) (*Service, error) {
	// 日志缓冲先行创建：控制台日志同步写入面板日志页（随后注册为全局 slog 输出）。
	logs := observability.NewLogBuffer(1000)
	logger := slog.New(&bufferHandler{inner: slog.Default().Handler(), buffer: logs})
	slog.SetDefault(logger)
	root, err := store.New(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("初始化数据目录失败：%w", err)
	}
	keys, err := store.OpenKeyring(root)
	if err != nil {
		return nil, fmt.Errorf("初始化主密钥失败：%w", err)
	}

	s := &Service{
		version:    cfg.Version,
		logger:     logger,
		root:       root,
		keys:       keys,
		useSingBox: cfg.UseSingBox,
		singBox:    cfg.SingBox,
		dueAttempt: map[string]time.Time{},
	}
	if err := s.loadSettings(); err != nil {
		return nil, err
	}

	// 访问密钥：显式提供则重设；否则首次生成并保存 Argon2id 哈希（实现方案 §7.1）。
	// 设置 ResetSecret 时强制重新生成并仅在控制台显示一次。
	switch {
	case cfg.Secret != "":
		s.settings.SecretHash = hashSecret(cfg.Secret)
		if err := s.persistSettings(); err != nil {
			return nil, err
		}
	case cfg.ResetSecret || s.settings.SecretHash == "":
		generated := randomSecret()
		s.settings.SecretHash = hashSecret(generated)
		s.secretOnce = generated
		if err := s.persistSettings(); err != nil {
			return nil, err
		}
	}
	verify := func(candidate string) bool { return verifySecret(s.settings.SecretHash, candidate) }

	// 内核适配器与可观测层。
	adapter := s.buildAdapter(logs)
	s.adapter = adapter
	s.collect = observability.NewCollector(adapter, logs, root)

	// 订阅、规则集、配置修订。
	s.subs = subscription.NewManager(root, keys)
	s.refreshDevNodes()
	s.ruleSets = ruleset.NewManager(root, logs)
	if err := s.ruleSets.SeedDefaults(); err != nil {
		return nil, err
	}
	// 规则集初始缓存（尽力而为）：优先把远程规则集落成本地副本，
	// 使托管编译引用本地文件，内核启动不再依赖外网
	// （大陆网络直连 GitHub Raw 超时会让 sing-box 初始化规则集时 FATAL 退出）。
	initCtx, initCancel := context.WithTimeout(context.Background(), 90*time.Second)
	for _, rs := range s.ruleSets.List() {
		if rs.Kind == "remote" && rs.LocalPath == "" {
			if err := s.ruleSets.Update(initCtx, rs.ID); err != nil {
				logger.Warn("规则集初始下载失败（进程仍会启动）", "rule_set", rs.Name, "err", err)
			}
		}
	}
	initCancel()
	s.cfgs, err = config.NewManager(root, adapter, config.Providers{
		Settings: s.Settings,
		Nodes:    s.subs.AllNodes,
		RuleSets: s.ruleSets.List,
	})
	if err != nil {
		return nil, err
	}

	// API 服务器与路由。
	s.server = api.NewServer(cfg.Version, verify, s.statusPayload, nil, logger)
	mux := api.RegisterRoutes(api.Deps{
		Version:      cfg.Version,
		Adapter:      adapter,
		Root:         root,
		Keys:         keys,
		Subs:         s.subs,
		RuleSets:     s.ruleSets,
		Configs:      s.cfgs,
		Collect:      s.collect,
		Server:       s.server,
		Settings:     s.Settings,
		SaveSettings: s.SaveSettings,
		CompileAndApply: func(ctx context.Context, createdBy, source string) (store.RevisionMeta, error) {
			rev, err := s.cfgs.CompileAndApply(ctx, createdBy, source)
			if err == nil {
				s.refreshDevNodes()
			}
			return rev, err
		},
		Logger: logger,
	})
	mux.Handle("/", s.staticHandler())
	s.server.Handler = mux

	// 首次启动：生成种子托管配置，让 Dashboard 立即有数据。
	if s.cfgs.LastApplied() == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := s.cfgs.CompileAndApply(ctx, "installer", "seed"); err != nil {
			logger.Warn("种子配置应用失败", "err", err)
		}
	}
	return s, nil
}

// BootstrapSecret 返回首次初始化生成的一次性密钥（仅在生成当次非空）。
func (s *Service) BootstrapSecret() string { return s.secretOnce }

// buildAdapter 依据 Config 组装开发适配器或真实 sing-box 适配器；日志统一写入传入的缓冲。
func (s *Service) buildAdapter(logs *observability.LogBuffer) core.Adapter {
	if s.useSingBox {
		opts := s.singBox
		if opts.Binary == "" {
			opts.Binary = s.detectKernelBinary()
		}
		if opts.ConfigPath == "" {
			opts.ConfigPath = "runtime/config.json" // 相对于 WorkDir（内核 CWD）
		}
		if opts.WorkDir == "" {
			opts.WorkDir = s.root.Dir
		}
		// 确保 WorkDir 和 ConfigPath 为绝对路径，避免 go run 临时目录等问题。
		if a, err := filepath.Abs(opts.WorkDir); err == nil {
			opts.WorkDir = a
		}
		if !filepath.IsAbs(opts.ConfigPath) {
			opts.ConfigPath = filepath.Join(opts.WorkDir, opts.ConfigPath)
		}
		sb := core.NewSingBoxAdapter(opts)
		sb.SetLogger(func(line core.LogLine) {
			logs.Append(line.Level, line.Component, line.Message)
		})
		sb.SetNodeResolver(s.nodeResolver())
		return sb
	}
	dev := core.NewDevAdapter()
	dev.SetLogger(func(line core.LogLine) {
		logs.Append(line.Level, line.Component, line.Message)
	})
	return dev
}

// Router 返回带中间件的完整 HTTP 处理器。
func (s *Service) Router() http.Handler { return s.server }

// refreshDevNodes 把订阅解析出的真实节点同步到开发适配器，替换演示假数据。
func (s *Service) refreshDevNodes() {
	dev, ok := s.adapter.(*core.DevAdapter)
	if !ok {
		return
	}
	records := s.subs.AllNodes()
	nodes := make([]core.Node, 0, len(records))
	for _, rec := range records {
		nodes = append(nodes, core.Node{
			ID:        nodeTag(rec),
			Name:      rec.DisplayName,
			Protocol:  rec.Type,
			Region:    guessRegion(rec.DisplayName),
			Available: true,
			SubID:     rec.SubID,
		})
	}
	dev.SetNodes(nodes)
}

// nodeResolver 把内核节点 tag 映射回 (订阅显示名, 归属订阅 ID)。
func (s *Service) nodeResolver() func(tag string) (string, string) {
	return func(tag string) (string, string) {
		if s.subs == nil {
			return "", ""
		}
		for _, rec := range s.subs.AllNodes() {
			var spec struct {
				Tag string `json:"tag"`
			}
			if json.Unmarshal(rec.Spec, &spec) != nil || spec.Tag != tag {
				continue
			}
			return rec.DisplayName, rec.SubID
		}
		return "", ""
	}
}

func nodeTag(rec store.NodeRecord) string {
	var spec struct {
		Tag string `json:"tag"`
	}
	if json.Unmarshal(rec.Spec, &spec) == nil && spec.Tag != "" {
		return spec.Tag
	}
	return "sub-" + rec.Fingerprint
}

// guessRegion 依据节点名做轻量地区猜测，用于展示。
func guessRegion(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "hk") || strings.Contains(name, "香港"):
		return "香港"
	case strings.Contains(lower, "jp") || strings.Contains(name, "日本"):
		return "日本"
	case strings.Contains(lower, "sg") || strings.Contains(name, "新加坡"):
		return "新加坡"
	case strings.Contains(lower, "tw") || strings.Contains(name, "台湾"):
		return "台湾"
	case strings.Contains(lower, "us") || strings.Contains(name, "美国"):
		return "美国"
	case strings.Contains(lower, "uk") || strings.Contains(name, "英国"):
		return "英国"
	case strings.Contains(lower, "kr") || strings.Contains(name, "韩国"):
		return "韩国"
	case strings.Contains(lower, "de") || strings.Contains(name, "德国"):
		return "德国"
	default:
		return "其他"
	}
}

// ---------- 设置 ----------

func (s *Service) loadSettings() error {
	err := s.root.LoadJSON("settings.json", &s.settings)
	if errors.Is(err, store.ErrNotFound) {
		s.settings = store.DefaultSettings()
		return s.persistSettings()
	}
	return err
}

// Settings 返回当前设置副本。
func (s *Service) Settings() store.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

// SaveSettings 校验并保存设置。
func (s *Service) SaveSettings(next store.Settings) error {
	// 公网监听的安全门禁（实现方案 §7.3）：局域网访问必须配置白名单。
	if next.LANAccess && len(next.Whitelist) == 0 {
		return errors.New("开启局域网访问前必须配置 CIDR 白名单")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = next
	return s.persistSettings()
}

func (s *Service) persistSettings() error {
	s.settings.UpdatedAt = time.Now().UTC()
	return s.root.SaveJSON("settings.json", s.settings)
}

// proxyMode 返回当前代理模式（rule/global/direct），未设置时回落 rule。
func (s *Service) proxyMode() string {
	m := s.Settings().ProxyMode
	if m == "" {
		return "rule"
	}
	return m
}

// detectKernelBinary 优先使用 dataDir/bin 下已下载的内核，其次回退到 PATH 里的 sing-box。
func (s *Service) detectKernelBinary() string {
	if p := s.root.Path("bin", "sing-box"); fileExists(p) {
		return absOr(p)
	}
	if p := s.root.Path("bin", "sing-box.exe"); fileExists(p) {
		return absOr(p)
	}
	return "sing-box"
}

func absOr(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ---------- 状态采样与 SSE ----------

func (s *Service) statusPayload() (api.StatusPayload, error) {
	if payload := s.server.LatestStatus(); payload.Service != "" {
		// 模式变更后缓存可能短暂滞后，这里始终用最新设置覆盖。
		payload.Mode = s.proxyMode()
		s.finalizePayload(&payload)
		return payload, nil
	}
	// 采样循环尚未产出时同步取一次。
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	status, err := s.adapter.GetStatus(ctx)
	if err != nil {
		return api.StatusPayload{}, err
	}
	payload := buildPayload(s.version, status)
	payload.Mode = s.proxyMode()
	s.finalizePayload(&payload)
	return payload, nil
}

// finalizePayload 校正模式相关的展示字段：直连模式下当前出口应为“直连”而非策略组选中节点；
// TUN 开启时明确展示“已启用”（适配器按平台探测的默认值在 macOS 上恒为“未启用”）。
func (s *Service) finalizePayload(p *api.StatusPayload) {
	if p.Mode == "direct" {
		p.CurrentProxy = "直连"
	}
	if s.Settings().TUNEnabled {
		p.Resources.TUN = "已启用"
	}
}

func buildPayload(version string, status core.Status) api.StatusPayload {
	payload := api.StatusPayload{
		Service:       "serverproxy",
		Version:       version,
		CoreVersion:   status.CoreVersion,
		UptimeSeconds: status.UptimeSeconds,
		CurrentProxy:  status.CurrentProxy,
		Mode:          status.Mode,
	}
	payload.Traffic.UploadRate = status.Traffic.UploadRate
	payload.Traffic.DownloadRate = status.Traffic.DownloadRate
	payload.Traffic.UploadTotal = status.Traffic.UploadTotal
	payload.Traffic.DownloadTotal = status.Traffic.DownloadTotal
	payload.Resources.MemoryMB = status.Resources.MemoryMB
	payload.Resources.Goroutines = status.Resources.Goroutines
	payload.Resources.TUN = status.Resources.TUN
	return payload
}

// Run 启动后台循环：1 秒采样 + SSE 广播（实现方案 §5.5），
// 并按计划执行订阅/规则集的定时更新。
func (s *Service) Run(ctx context.Context) error {
	if lc, ok := s.adapter.(core.Lifecycle); ok {
		if err := lc.Start(ctx); err != nil {
			return fmt.Errorf("启动内核失败：%w", err)
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = lc.Stop(stopCtx)
		}()
	}
	s.collect.Start(ctx)
	go s.schedulerLoop(ctx)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	// 以启动时的最新序号为起点，后续仅推送增量日志，避免向新连接的客户端重放历史缓冲。
	logSeq := s.collect.Logs().LatestSeq()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// 实时推送新增日志；即使状态采样失败也照常推送。
			if entries := s.collect.Logs().Since(logSeq); len(entries) > 0 {
				logSeq = entries[len(entries)-1].Seq
				if frame, err := json.Marshal(entries); err == nil {
					s.server.Broadcast("logs", frame)
				}
			}
			status, err := s.adapter.GetStatus(ctx)
			if err != nil {
				continue
			}
			s.collect.Observe(status)
			payload := buildPayload(s.version, status)
			payload.Mode = s.proxyMode()
			s.finalizePayload(&payload)
			s.server.SetLatestStatus(payload)
			frame, _ := json.Marshal(payload)
			s.server.Broadcast("status", frame)
		}
	}
}

// schedulerLoop 每分钟检查一次到期任务；任务串行执行，避免与 Web/CLI 并发改写（实现方案 §4.2）。
func (s *Service) schedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDueJobs(ctx)
		}
	}
}

func (s *Service) runDueJobs(ctx context.Context) {
	now := time.Now()
	anySuccess := false
	for _, sub := range s.subs.List() {
		if !sub.Enabled {
			continue
		}
		interval := subscription.ScheduleInterval(sub.Schedule)
		// 按“上次尝试”退避：更新失败时 LastUpdated 不前进，
		// 若不记录尝试时间，调度器会每分钟重试一次。
		s.dueMu.Lock()
		lastAttempt := s.dueAttempt[sub.ID]
		s.dueMu.Unlock()
		if now.Sub(lastAttempt) < interval {
			continue
		}
		if now.Sub(sub.LastUpdated) < interval {
			continue
		}
		s.dueMu.Lock()
		s.dueAttempt[sub.ID] = now
		s.dueMu.Unlock()
		if _, err := s.subs.Update(ctx, sub.ID); err != nil {
			s.logger.Warn("定时订阅更新失败", "subscription", sub.Name, "err", err)
			continue
		}
		anySuccess = true
		s.logger.Info("定时订阅更新完成", "subscription", sub.Name)
	}
	for _, rs := range s.ruleSets.List() {
		if rs.Kind != "remote" {
			continue
		}
		if now.Sub(rs.LastUpdated) < ruleset.DueInterval(rs.Interval) {
			continue
		}
		if err := s.ruleSets.Update(ctx, rs.ID); err != nil {
			s.logger.Warn("定时规则集更新失败", "rule_set", rs.Name, "err", err)
		}
	}
	if anySuccess && s.cfgs.CurrentMode() == "managed" {
		if _, err := s.cfgs.CompileAndApply(ctx, "scheduler", "subscription-update"); err != nil {
			s.logger.Warn("订阅驱动的配置应用失败", "err", err)
		} else {
			s.refreshDevNodes()
		}
	}
}

// ---------- 静态资源 ----------

func (s *Service) staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(sub, path); err != nil {
			// SPA 回退。
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

// ---------- 密钥派生 ----------

func randomSecret() string {
	raw := make([]byte, 18)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func hashSecret(secret string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hash := argon2.IDKey([]byte(secret), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 64*1024, 3, 2,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

func verifySecret(encoded, candidate string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int32
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(candidate), salt, t, m, p, uint32(len(expected)))
	return subtleEqual(expected, actual)
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
