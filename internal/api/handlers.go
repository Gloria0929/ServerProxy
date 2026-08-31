package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"proxypanel/internal/config"
	"proxypanel/internal/core"
	"proxypanel/internal/kernel"
	"proxypanel/internal/observability"
	"proxypanel/internal/ruleset"
	"proxypanel/internal/store"
	"proxypanel/internal/subscription"
)

// Deps 处理器依赖集合，由 app 层组装。
type Deps struct {
	Version  string
	Adapter  core.Adapter
	Root     *store.Root
	Keys     *store.Keyring
	Subs     *subscription.Manager
	RuleSets *ruleset.Manager
	Configs  *config.Manager
	Collect  *observability.Collector
	Server   *Server

	Settings     func() store.Settings
	SaveSettings func(store.Settings) error

	// CompileAndApply 以当前期望状态重新编译并应用托管配置。
	CompileAndApply func(ctx context.Context, createdBy, source string) (store.RevisionMeta, error)

	Logger interface{ Info(string, ...any) }
}

// RegisterRoutes 注册全部业务路由并返回 mux。
func RegisterRoutes(d Deps) *http.ServeMux {
	mux := http.NewServeMux()

	// ---- 鉴权 ----
	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Secret string `json:"secret"`
		}
		if err := readBody(r, &body); err != nil {
			writeError(w, TraceID(r.Context()), 400, "bad_request", err.Error())
			return
		}
		trace := TraceID(r.Context())
		if !d.Server.VerifySecret(body.Secret) {
			d.Server.recordLoginFailure(d.Server.clientIP(r))
			d.Collect.Audit("anonymous", d.Server.clientIP(r), "auth.login", "", "failed", trace)
			writeError(w, trace, 401, "unauthorized", "访问密钥不正确")
			return
		}
		token, csrf := d.Server.createSession()
		http.SetCookie(w, &http.Cookie{
			Name: "sp_session", Value: token, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
		})
		d.Collect.Audit("web", d.Server.clientIP(r), "auth.login", "", "ok", trace)
		writeJSON(w, 200, map[string]any{"csrf_token": csrf})
	})

	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		d.Server.destroySession(r)
		w.Header().Add("Set-Cookie", "sp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("GET /api/v1/auth/session", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"authenticated": true,
			"version":       d.Version,
			"csrf_token":    d.Server.CurrentCSRF(r),
		})
	})

	// ---- 系统状态 ----
	mux.HandleFunc("GET /api/v1/system/status", func(w http.ResponseWriter, r *http.Request) {
		payload, err := d.Server.StatusLoop()
		if err != nil {
			writeError(w, TraceID(r.Context()), 502, "core", err.Error())
			return
		}
		writeJSON(w, 200, payload)
	})

	mux.HandleFunc("GET /api/v1/system/capabilities", func(w http.ResponseWriter, r *http.Request) {
		caps := d.Adapter.GetCapabilities(r.Context())
		caps.FeatureNotices["profile_mode"] = profileModeNotice(d)
		writeJSON(w, 200, caps)
	})

	mux.HandleFunc("POST /api/v1/system/restart", func(w http.ResponseWriter, r *http.Request) {
		if err := d.Adapter.Restart(r.Context()); err != nil {
			writeError(w, TraceID(r.Context()), 502, "core", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "system.restart", "", "ok", TraceID(r.Context()))
		d.Collect.Logs().Append("warn", "control-plane", "收到重启指令，内核状态已重置")
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("POST /api/v1/system/install-kernel", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Version string `json:"version"`
		}
		_ = readBody(r, &body) // 允许空 body，用最新版本
		output := filepath.Join(d.Root.Dir, "bin", kernel.BinaryName(kernel.CurrentPlatform()))
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()
		path, err := kernel.Install(ctx, body.Version, "", output)
		if err != nil {
			d.Collect.Audit(actor(r), d.Server.clientIP(r), "kernel.install", "", "failed", TraceID(r.Context()))
			writeError(w, TraceID(r.Context()), 502, "kernel", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "kernel.install", path, "ok", TraceID(r.Context()))
		writeJSON(w, 200, map[string]any{"ok": true, "path": path, "version": body.Version})
	})

	// ---- 策略组与节点 ----
	mux.HandleFunc("GET /api/v1/proxies/groups", func(w http.ResponseWriter, r *http.Request) {
		groups, err := d.Adapter.ListGroups(r.Context())
		if err != nil {
			writeError(w, TraceID(r.Context()), 502, "core", err.Error())
			return
		}
		writeJSON(w, 200, groups)
	})

	mux.HandleFunc("PATCH /api/v1/proxies/groups/{tag}/selection", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			NodeID string `json:"node_id"`
		}
		if err := readBody(r, &body); err != nil || body.NodeID == "" {
			writeError(w, TraceID(r.Context()), 400, "bad_request", "缺少 node_id")
			return
		}
		tag := r.PathValue("tag")
		if err := d.Adapter.SelectNode(r.Context(), tag, body.NodeID); err != nil {
			writeError(w, TraceID(r.Context()), 400, "select", err.Error())
			return
		}
		// Selector 切换不触发重载（实现方案 §6.1）。
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "proxy.select", tag+"→"+body.NodeID, "ok", TraceID(r.Context()))
		writeJSON(w, 200, map[string]any{"ok": true, "group": tag, "selected": body.NodeID})
	})

	mux.HandleFunc("POST /api/v1/proxies/delay-tests", func(w http.ResponseWriter, r *http.Request) {
		n, err := d.Adapter.TestDelay(r.Context())
		if err != nil {
			writeError(w, TraceID(r.Context()), 502, "core", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "proxy.delay_test", "", "ok", TraceID(r.Context()))
		writeJSON(w, 200, map[string]any{"updated": n})
	})

	// ---- 订阅 ----
	mux.HandleFunc("GET /api/v1/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, subscriptionViews(d))
	})

	mux.HandleFunc("POST /api/v1/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name     string `json:"name"`
			URL      string `json:"url"`
			Schedule string `json:"schedule"`
		}
		if err := readBody(r, &body); err != nil {
			writeError(w, TraceID(r.Context()), 400, "bad_request", err.Error())
			return
		}
		sub, err := d.Subs.Add(r.Context(), body.Name, body.URL, body.Schedule)
		if err != nil {
			writeError(w, TraceID(r.Context()), 400, "subscription", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "subscription.create", sub.ID, "ok", TraceID(r.Context()))
		// 立即尝试首次更新，成功后进入配置事务。
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		result, updErr := d.Subs.Update(ctx, sub.ID)
		if updErr != nil {
			d.Collect.Logs().Append("warn", "subscription", "订阅 "+sub.Name+" 首次更新失败："+updErr.Error())
		} else if result != nil {
			d.Collect.Logs().Append("info", "subscription", "订阅 "+sub.Name+" 导入 "+strconv.Itoa(len(result.Nodes))+" 个节点，"+strconv.Itoa(len(result.Warnings))+" 条转换提示")
			maybeCompileAndApply(d, r.Context(), "subscription-update")
		}
		writeJSON(w, 201, findSubscriptionView(d, sub.ID))
	})

	mux.HandleFunc("DELETE /api/v1/subscriptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.Subs.Delete(id); err != nil {
			writeError(w, TraceID(r.Context()), 404, "not_found", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "subscription.delete", id, "ok", TraceID(r.Context()))
		maybeCompileAndApply(d, r.Context(), "subscription-update")
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("GET /api/v1/subscriptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		rawURL, err := d.Subs.URL(id)
		if err != nil {
			writeError(w, TraceID(r.Context()), 404, "not_found", "订阅不存在")
			return
		}
		for _, sub := range d.Subs.List() {
			if sub.ID == id {
				writeJSON(w, 200, map[string]any{
					"id":       sub.ID,
					"name":     sub.Name,
					"url":      rawURL,
					"schedule": sub.Schedule,
					"enabled":  sub.Enabled,
				})
				return
			}
		}
		writeError(w, TraceID(r.Context()), 404, "not_found", "订阅不存在")
	})

	mux.HandleFunc("PATCH /api/v1/subscriptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name     string `json:"name"`
			URL      string `json:"url"`
			Schedule string `json:"schedule"`
			Enabled  *bool  `json:"enabled"`
		}
		if err := readBody(r, &body); err != nil {
			writeError(w, TraceID(r.Context()), 400, "bad_request", err.Error())
			return
		}
		sub, err := d.Subs.Patch(r.PathValue("id"), body.Name, body.URL, body.Schedule, body.Enabled)
		if err != nil {
			code := 400
			if errors.Is(err, store.ErrNotFound) {
				code = 404
			}
			writeError(w, TraceID(r.Context()), code, "subscription", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "subscription.edit", sub.ID, "ok", TraceID(r.Context()))
		// 更换了地址则立即拉取一次并重新编译。
		if body.URL != "" {
			if _, updErr := d.Subs.Update(r.Context(), sub.ID); updErr != nil {
				d.Collect.Logs().Append("warn", "subscription", "订阅 "+sub.Name+" 更新失败："+updErr.Error())
			} else {
				maybeCompileAndApply(d, r.Context(), "subscription-update")
			}
		}
		writeJSON(w, 200, findSubscriptionView(d, sub.ID))
	})

	mux.HandleFunc("POST /api/v1/subscriptions/{id}/update", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		result := runSubscriptionUpdate(d, r.Context(), id)
		writeJSON(w, result.ok(), result)
	})

	mux.HandleFunc("POST /api/v1/subscriptions/all/update", func(w http.ResponseWriter, r *http.Request) {
		type item struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			OK    bool   `json:"ok"`
			Error string `json:"error,omitempty"`
		}
		var results []item
		anySuccess := false
		for _, sub := range d.Subs.List() {
			if !sub.Enabled {
				continue
			}
			_, err := d.Subs.Update(r.Context(), sub.ID)
			ok := err == nil
			if ok {
				anySuccess = true
			}
			e := ""
			if err != nil {
				e = err.Error()
			}
			results = append(results, item{ID: sub.ID, Name: sub.Name, OK: ok, Error: e})
		}
		if anySuccess {
			maybeCompileAndApply(d, r.Context(), "subscription-update")
		}
		writeJSON(w, 200, map[string]any{"results": results})
	})

	// ---- 规则集 ----
	mux.HandleFunc("GET /api/v1/rule-sets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, d.RuleSets.List())
	})

	mux.HandleFunc("POST /api/v1/rule-sets", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name     string `json:"name"`
			URL      string `json:"url"`
			Format   string `json:"format"`
			Interval string `json:"interval"`
		}
		if err := readBody(r, &body); err != nil {
			writeError(w, TraceID(r.Context()), 400, "bad_request", err.Error())
			return
		}
		record, err := d.RuleSets.Add(body.Name, body.URL, body.Format, body.Interval)
		if err != nil {
			writeError(w, TraceID(r.Context()), 400, "rule_set", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "rule_set.create", record.ID, "ok", TraceID(r.Context()))
		writeJSON(w, 201, record)
	})

	mux.HandleFunc("POST /api/v1/rule-sets/{id}/update", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.RuleSets.Update(r.Context(), id); err != nil {
			d.Collect.Audit(actor(r), d.Server.clientIP(r), "rule_set.update", id, "failed", TraceID(r.Context()))
			writeError(w, TraceID(r.Context()), 502, "rule_set", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "rule_set.update", id, "ok", TraceID(r.Context()))
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	// ---- 连接 ----
	mux.HandleFunc("GET /api/v1/connections", func(w http.ResponseWriter, r *http.Request) {
		conns, err := d.Adapter.ListConnections(r.Context())
		if err != nil {
			writeError(w, TraceID(r.Context()), 502, "core", err.Error())
			return
		}
		writeJSON(w, 200, conns)
	})

	mux.HandleFunc("DELETE /api/v1/connections/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.Adapter.CloseConnection(r.Context(), id); err != nil {
			writeError(w, TraceID(r.Context()), 404, "not_found", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "connection.close", id, "ok", TraceID(r.Context()))
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	// ---- 日志 / 指标 / 审计 ----
	mux.HandleFunc("GET /api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 200
		}
		writeJSON(w, 200, d.Collect.Logs().Query(r.URL.Query().Get("q"), r.URL.Query().Get("level"), limit))
	})

	mux.HandleFunc("DELETE /api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		d.Collect.Logs().Clear()
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "logs.clear", "", "ok", TraceID(r.Context()))
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("GET /api/v1/metrics/history", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 600 {
			limit = 120
		}
		writeJSON(w, 200, d.Collect.History(limit))
	})

	mux.HandleFunc("GET /api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		events := d.Root.LoadAudit(200)
		if events == nil {
			events = []store.AuditEvent{}
		}
		writeJSON(w, 200, events)
	})

	// ---- 配置事务 ----
	mux.HandleFunc("GET /api/v1/config/revisions", func(w http.ResponseWriter, r *http.Request) {
		type view struct {
			ID        string `json:"id"`
			CreatedAt string `json:"created_at"`
			State     string `json:"state"`
			Summary   string `json:"summary"`
			Checksum  string `json:"checksum"`
		}
		out := []view{}
		for _, rev := range d.Configs.List() {
			out = append(out, view{ID: rev.ID, CreatedAt: rev.CreatedAt.Format(time.RFC3339), State: rev.State, Summary: rev.Summary, Checksum: shortHash(rev.Checksum)})
		}
		writeJSON(w, 200, out)
	})

	mux.HandleFunc("POST /api/v1/config/validate", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Config string `json:"config"`
		}
		if err := readBody(r, &body); err != nil {
			writeError(w, TraceID(r.Context()), 400, "bad_request", err.Error())
			return
		}
		summary, err := config.Validate([]byte(body.Config))
		if err != nil {
			writeError(w, TraceID(r.Context()), 400, "invalid", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"message": summary})
	})

	mux.HandleFunc("POST /api/v1/config/apply", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Config string `json:"config"`
		}
		if err := readBody(r, &body); err != nil {
			writeError(w, TraceID(r.Context()), 400, "bad_request", err.Error())
			return
		}
		// 编辑器提交完整原生 JSON → 转为非托管配置档（实现方案 §4.1）。
		if err := d.SaveSettings(withMode(d.Settings(), "unmanaged")); err != nil {
			writeError(w, TraceID(r.Context()), 500, "storage", err.Error())
			return
		}
		rev, err := d.Configs.Apply(r.Context(), []byte(body.Config), "editor", actor(r), false)
		if err != nil {
			writeError(w, TraceID(r.Context()), 400, "apply", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "config.apply", rev.ID, "ok", TraceID(r.Context()))
		writeJSON(w, 200, map[string]any{"id": rev.ID, "state": rev.State, "summary": rev.Summary})
	})

	mux.HandleFunc("POST /api/v1/config/restore/{id}", func(w http.ResponseWriter, r *http.Request) {
		rev, err := d.Configs.Restore(r.Context(), r.PathValue("id"), actor(r))
		if err != nil {
			writeError(w, TraceID(r.Context()), 400, "restore", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "config.restore", rev.ID, "ok", TraceID(r.Context()))
		writeJSON(w, 200, map[string]any{"id": rev.ID, "state": rev.State, "summary": rev.Summary})
	})

	// ---- 设置 ----
	mux.HandleFunc("GET /api/v1/settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, d.Settings())
	})

	mux.HandleFunc("PATCH /api/v1/settings", func(w http.ResponseWriter, r *http.Request) {
		var patch struct {
			LANAccess    *bool    `json:"lan_access"`
			Whitelist    []string `json:"whitelist"`
			TUNEnabled   *bool    `json:"tun_enabled"`
			DNSPreset    string   `json:"dns_preset"`
			MixedPort    *int     `json:"mixed_port"`
			ProxyMode    string   `json:"proxy_mode"`
			ProxyDomains []string `json:"proxy_domains"`
		}
		if err := readBody(r, &patch); err != nil {
			writeError(w, TraceID(r.Context()), 400, "bad_request", err.Error())
			return
		}
		settings := d.Settings()
		wasManaged := d.Configs.CurrentMode() == "managed"
		if patch.TUNEnabled != nil && *patch.TUNEnabled && os.Geteuid() != 0 {
			writeError(w, TraceID(r.Context()), 400, "tun_permission", "启用 TUN 需要管理员权限：请以 root（sudo）权限启动面板服务后再开启")
			return
		}
		if patch.LANAccess != nil {
			settings.LANAccess = *patch.LANAccess
		}
		if patch.Whitelist != nil {
			settings.Whitelist = patch.Whitelist
		}
		if patch.TUNEnabled != nil {
			settings.TUNEnabled = *patch.TUNEnabled
		}
		if patch.DNSPreset != "" {
			settings.DNSPreset = patch.DNSPreset
		}
		if patch.MixedPort != nil {
			settings.MixedPort = *patch.MixedPort
		}
		if patch.ProxyDomains != nil {
			domains, err := normalizeDomains(patch.ProxyDomains)
			if err != nil {
				writeError(w, TraceID(r.Context()), 400, "bad_request", err.Error())
				return
			}
			settings.ProxyDomains = domains
		}
		if patch.ProxyMode != "" {
			switch patch.ProxyMode {
			case "rule", "global", "direct":
				settings.ProxyMode = patch.ProxyMode
			default:
				writeError(w, TraceID(r.Context()), 400, "bad_request", "无效的代理模式")
				return
			}
		}
		// 代理模式与强制代理域名都会改变路由编译结果：即使当前是自定义（非托管）配置档，
		// 也恢复为面板托管编译，保证设置真正生效。
		if !wasManaged && (patch.ProxyMode != "" || patch.ProxyDomains != nil) {
			settings.Mode = "managed"
			d.Collect.Logs().Append("info", "config", "路由设置更新：自定义配置档已恢复为面板托管编译")
		}
		settings.UpdatedAt = time.Now().UTC()
		if err := d.SaveSettings(settings); err != nil {
			writeError(w, TraceID(r.Context()), 500, "storage", err.Error())
			return
		}
		d.Collect.Audit(actor(r), d.Server.clientIP(r), "settings.update", "", "ok", TraceID(r.Context()))
		// 仅代理模式变更时通过 Clash API 直接切换，不触发内核重启（避免 TUN 重启导致 SSH 断开）。
		modeOnly := wasManaged && patch.ProxyMode != "" &&
			patch.LANAccess == nil && patch.TUNEnabled == nil &&
			patch.DNSPreset == "" && patch.MixedPort == nil &&
			patch.ProxyDomains == nil
		if modeOnly {
			if err := d.Adapter.SetMode(r.Context(), patch.ProxyMode); err != nil {
				writeError(w, TraceID(r.Context()), 502, "core", err.Error())
				return
			}
		} else if wasManaged || patch.ProxyMode != "" || patch.ProxyDomains != nil {
			if _, err := d.CompileAndApply(r.Context(), actor(r), "settings"); err != nil {
				writeError(w, TraceID(r.Context()), 400, "apply", err.Error())
				return
			}
		}
		writeJSON(w, 200, settings)
	})

	// ---- SSE 实时通道 ----
	mux.HandleFunc("GET /api/v1/events", sseHandler(d))

	return mux
}

// normalizeDomains 规范化域名列表：去空白、小写、剥离前导通配符，并校验合法域名。
func normalizeDomains(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		d := strings.TrimSpace(raw)
		if d == "" {
			continue
		}
		d = strings.ToLower(d)
		d = strings.TrimPrefix(d, "*.")
		d = strings.TrimPrefix(d, ".")
		if strings.ContainsAny(d, "/: \t") {
			return nil, fmt.Errorf("域名格式无效（只接受纯域名，如 example.com）：%s", raw)
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out, nil
}

func sseHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, TraceID(r.Context()), 500, "sse", "连接不支持流式响应")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")

		s := d.Server
		ch := make(chan []byte, 8)
		s.sseMu.Lock()
		s.sseClients[ch] = struct{}{}
		s.sseMu.Unlock()
		defer func() {
			s.sseMu.Lock()
			delete(s.sseClients, ch)
			s.sseMu.Unlock()
		}()

		// 立即推送一次当前状态。
		if payload, err := s.StatusLoop(); err == nil {
			frame, _ := json.Marshal(payload)
			_, _ = w.Write(append(append([]byte("event: status\ndata: "), frame...), '\n', '\n'))
			flusher.Flush()
		}

		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case frame := <-ch:
				if _, err := w.Write(frame); err != nil {
					return
				}
				flusher.Flush()
			case <-ping.C:
				if _, err := w.Write([]byte(": ping\n\n")); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}

// ---------- 辅助 ----------

func readBody(r *http.Request, target any) error {
	defer io.Copy(io.Discard, r.Body)
	data, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("请求体为空")
	}
	return json.Unmarshal(data, target)
}

func actor(r *http.Request) string { return "web" }

func shortHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

type updateOutcome struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (u updateOutcome) ok() int {
	if u.OK {
		return 200
	}
	return 502
}

// runSubscriptionUpdate 更新单个订阅并按需触发配置编译。
func runSubscriptionUpdate(d Deps, ctx context.Context, id string) updateOutcome {
	result, err := d.Subs.Update(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return updateOutcome{OK: false, Error: "订阅不存在"}
		}
		d.Collect.Audit(actor(&http.Request{}), "", "subscription.update", id, "failed", "")
		return updateOutcome{OK: false, Error: err.Error()}
	}
	if result != nil {
		d.Collect.Logs().Append("info", "subscription", "订阅更新成功："+strconv.Itoa(len(result.Nodes))+" 个节点")
		maybeCompileAndApply(d, ctx, "subscription-update")
	}
	return updateOutcome{OK: true}
}

// maybeCompileAndApply 托管模式下用最新期望状态重新编译并应用。
func maybeCompileAndApply(d Deps, ctx context.Context, source string) {
	if d.Configs.CurrentMode() != "managed" {
		d.Collect.Logs().Append("info", "config", "当前为非托管配置档，跳过订阅驱动的自动编译")
		return
	}
	rev, err := d.CompileAndApply(ctx, "scheduler", source)
	if err != nil {
		d.Collect.Logs().Append("error", "config", "订阅驱动的配置应用失败："+err.Error())
		return
	}
	d.Collect.Logs().Append("info", "config", "已应用配置版本 "+rev.ID+"："+rev.Summary)
}

func subscriptionViews(d Deps) []map[string]any {
	out := []map[string]any{}
	for _, sub := range d.Subs.List() {
		out = append(out, map[string]any{
			"id":           sub.ID,
			"name":         sub.Name,
			"url_preview":  d.Subs.PreviewURL(sub),
			"schedule":     sub.Schedule,
			"enabled":      sub.Enabled,
			"nodes":        sub.NodeCount,
			"last_updated": sub.LastUpdated.Format(time.RFC3339),
			"status":       sub.LastStatus,
			"warnings":     sub.Warnings,
		})
	}
	return out
}

func findSubscriptionView(d Deps, id string) map[string]any {
	for _, view := range subscriptionViews(d) {
		if view["id"] == id {
			return view
		}
	}
	return nil
}

func withMode(settings store.Settings, mode string) store.Settings {
	settings.Mode = mode
	settings.UpdatedAt = time.Now().UTC()
	return settings
}

func profileModeNotice(d Deps) string {
	if d.Configs.CurrentMode() == "managed" {
		return "托管配置档：订阅更新会自动重新编译并应用配置。"
	}
	return "非托管配置档：订阅仍会更新节点，但不会自动改写当前配置。"
}
