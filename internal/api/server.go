// Package api 提供 Web 控制面的 HTTP/SSE 服务：会话鉴权、CSRF、
// 登录限流、安全响应头、统一错误结构与静态资源（实现方案 §6、§7）。
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Session 会话记录。
type Session struct {
	CSRF    string
	Expires time.Time
}

// sessionTTL 会话有效期；登录后滑动续期。
const sessionTTL = 24 * time.Hour

type rateWindow struct {
	failures int
	resetAt  time.Time
}

// Server HTTP 服务。
type Server struct {
	Version      string
	VerifySecret func(string) bool
	StatusLoop   func() (StatusPayload, error)
	Handler      http.Handler // 业务路由（已含鉴权），由 app 层组装

	mu       sync.Mutex
	sessions map[string]*Session
	failures map[string]*rateWindow

	sseMu      sync.Mutex
	sseClients map[chan []byte]struct{}

	statusMu     sync.Mutex
	statusLatest StatusPayload

	logger *slog.Logger
}

// SetLatestStatus 缓存最新一次状态采样（由采样循环调用）。
func (s *Server) SetLatestStatus(payload StatusPayload) {
	s.statusMu.Lock()
	s.statusLatest = payload
	s.statusMu.Unlock()
}

// LatestStatus 返回缓存的状态采样。
func (s *Server) LatestStatus() StatusPayload {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	return s.statusLatest
}

// StatusPayload /system/status 与 SSE status 事件的负载。
type StatusPayload struct {
	Service       string `json:"service"`
	Version       string `json:"version"`
	CoreVersion   string `json:"core_version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	CurrentProxy  string `json:"current_proxy"`
	Mode          string `json:"mode"`
	Traffic       struct {
		UploadRate    float64 `json:"upload_rate"`
		DownloadRate  float64 `json:"download_rate"`
		UploadTotal   int64   `json:"upload_total"`
		DownloadTotal int64   `json:"download_total"`
	} `json:"traffic"`
	Resources struct {
		MemoryMB   int    `json:"memory_mb"`
		Goroutines int    `json:"goroutines"`
		TUN        string `json:"tun"`
	} `json:"resources"`
}

// NewServer 创建服务。
func NewServer(version string, verify func(string) bool, statusLoop func() (StatusPayload, error), handler http.Handler, logger *slog.Logger) *Server {
	return &Server{
		Version:      version,
		VerifySecret: verify,
		StatusLoop:   statusLoop,
		Handler:      handler,
		sessions:     map[string]*Session{},
		failures:     map[string]*rateWindow{},
		sseClients:   make(map[chan []byte]struct{}),
		logger:       logger,
	}
}

// ---------- 会话管理 ----------

func randomToken() string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *Server) createSession() (token, csrf string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, csrf = randomToken(), randomToken()
	s.sessions[token] = &Session{CSRF: csrf, Expires: time.Now().Add(sessionTTL)}
	return token, csrf
}

func (s *Server) sessionFrom(r *http.Request) *Session {
	cookie, err := r.Cookie("sp_session")
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[cookie.Value]
	if sess == nil {
		return nil
	}
	if time.Now().After(sess.Expires) {
		delete(s.sessions, cookie.Value)
		return nil
	}
	sess.Expires = time.Now().Add(sessionTTL) // 滑动续期
	return sess
}

func (s *Server) destroySession(r *http.Request) {
	if cookie, err := r.Cookie("sp_session"); err == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.sessions, cookie.Value)
	}
}

// CurrentCSRF 返回当前请求会话的 CSRF 令牌；无有效会话返回空串。
// 供 /auth/session 在页面刷新后把令牌重新交给前端。
func (s *Server) CurrentCSRF(r *http.Request) string {
	sess := s.sessionFrom(r)
	if sess == nil {
		return ""
	}
	return sess.CSRF
}

// loginLimit 记录每 IP 登录失败次数；1 分钟窗口内 5 次失败触发限流。
func (s *Server) loginLimited(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.failures[ip]
	if entry == nil || time.Now().After(entry.resetAt) {
		return false
	}
	return entry.failures >= 5
}

func (s *Server) recordLoginFailure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.failures[ip]
	if entry == nil || time.Now().After(entry.resetAt) {
		s.failures[ip] = &rateWindow{failures: 1, resetAt: time.Now().Add(time.Minute)}
		return
	}
	entry.failures++
}

// ---------- 中间件 ----------

type traceKey struct{}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceID := randomToken()[:12]
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Error("panic", "trace_id", traceID, "err", fmt.Sprint(rec))
			writeError(w, traceID, http.StatusInternalServerError, "internal", "服务内部错误，请查看日志")
		}
	}()

	ctx := withTrace(r.Context(), traceID)
	r = r.WithContext(ctx)

	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.serveAPI(w, r, traceID)
		return
	}
	s.Handler.ServeHTTP(w, r)
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request, traceID string) {
	path := r.URL.Path

	// 登录端点仅做限流。
	if path == "/api/v1/auth/login" && r.Method == http.MethodPost {
		ip := s.clientIP(r)
		if s.loginLimited(ip) {
			w.Header().Set("Retry-After", "30")
			writeError(w, traceID, http.StatusTooManyRequests, "rate_limited", "登录失败次数过多，请稍后再试")
			return
		}
		s.Handler.ServeHTTP(w, r)
		return
	}

	// 其余 API 全部要求会话。
	if s.sessionFrom(r) == nil {
		writeError(w, traceID, http.StatusUnauthorized, "unauthorized", "未登录或会话已过期")
		return
	}

	// 写操作要求 CSRF 头。
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		sess := s.sessionFrom(r)
		if sess == nil || r.Header.Get("X-CSRF-Token") != sess.CSRF {
			writeError(w, traceID, http.StatusForbidden, "csrf", "缺少有效的 CSRF 令牌")
			return
		}
	}
	s.Handler.ServeHTTP(w, r)
}

// clientIP 尊重受信任反代的 X-Forwarded-For（实现方案 §7.3）。
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

// ---------- SSE ----------

// Broadcast 向全部 SSE 客户端推送一条事件；慢客户端直接丢弃本帧。
func (s *Server) Broadcast(event string, payload []byte) {
	frame := make([]byte, 0, len(event)+len(payload)+16)
	frame = append(frame, []byte("event: "+event+"\ndata: ")...)
	frame = append(frame, payload...)
	frame = append(frame, []byte("\n\n")...)

	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for ch := range s.sseClients {
		select {
		case ch <- frame:
		default: // 有界队列已满：丢弃，不阻塞代理
		}
	}
}

// ---------- JSON 工具 ----------

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, traceID string, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"trace_id": traceID,
		"code":     code,
		"message":  message,
	})
}

// TraceID 从上下文取请求追踪 ID。
func TraceID(ctx context.Context) string {
	id, _ := ctx.Value(traceKey{}).(string)
	return id
}

func withTrace(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceKey{}, id)
}
