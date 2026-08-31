// Package store 提供文件型持久化：JSON 原子写入、校验和、主密钥加密。
// V0.1 用文件仓储替代 SQLite（运行配置保持可脱离数据库恢复，实现方案 §4.1），
// 领域层只依赖这里的类型与读写函数，后续可平替为 SQLite 实现。
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrNotFound 表示记录不存在。
var ErrNotFound = errors.New("record not found")

// Root 运行数据根目录。
type Root struct {
	Dir string
}

// New 创建目录结构并返回仓储。
func New(dir string) (*Root, error) {
	for _, sub := range []string{"", "secrets", "snapshots", "revisions", "runtime", "backups", "rules"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Root{Dir: dir}, nil
}

// Path 返回相对路径的绝对位置。
func (r *Root) Path(rel ...string) string {
	return filepath.Join(append([]string{r.Dir}, rel...)...)
}

// SaveJSON 原子写入 JSON 文件（tmp + rename，实现方案 §4.2）。
func (r *Root) SaveJSON(rel string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return r.WriteFileAtomic(rel, data)
}

// WriteFileAtomic 以临时文件 + rename 的方式原子写入。
func (r *Root) WriteFileAtomic(rel string, data []byte) error {
	full := r.Path(rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".tmp-*")
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
	return os.Rename(tmpName, full)
}

// LoadJSON 读取 JSON 文件；文件不存在返回 ErrNotFound。
func (r *Root) LoadJSON(rel string, value any) error {
	data, err := os.ReadFile(r.Path(rel))
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return nil
}

// Checksum 返回内容的 SHA-256 十六进制串。
func Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ---------- 主密钥与敏感字段加密（实现方案 §4.3） ----------

// Keyring 管理每机生成的主密钥。
type Keyring struct {
	aead cipher.AEAD
}

// OpenKeyring 读取或生成 dataDir/secrets/master.key（0600，仅服务用户可读）。
func OpenKeyring(r *Root) (*Keyring, error) {
	path := r.Path("secrets", "master.key")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return nil, err
		}
		data = raw
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("master.key 长度异常：%d", len(data))
	}
	block, err := aes.NewCipher(data)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Keyring{aead: aead}, nil
}

// Encrypt 加密敏感字段，返回 base64 密文。
func (k *Keyring) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := k.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt 解密敏感字段。
func (k *Keyring) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	size := k.aead.NonceSize()
	if len(raw) < size {
		return "", errors.New("密文长度不足")
	}
	plain, err := k.aead.Open(nil, raw[:size], raw[size:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ---------- 领域记录 ----------

// Settings 全局设置（settings 表）。
type Settings struct {
	WebListen      string    `json:"web_listen"`
	SecretHash     string    `json:"secret_hash"`
	Mode           string    `json:"mode"`       // managed | unmanaged
	ProxyMode      string    `json:"proxy_mode"` // rule | global | direct
	Whitelist      []string  `json:"whitelist"`
	LANAccess      bool      `json:"lan_access"`
	TUNEnabled     bool      `json:"tun_enabled"`
	TUNName        string    `json:"tun_name"`
	ProxyDomains   []string  `json:"proxy_domains"` // 强制走代理的域名（规则模式生效）
	DNSPreset      string    `json:"dns_preset"`    // fakeip | real
	MixedPort      int       `json:"mixed_port"`
	TrustedProxies []string  `json:"trusted_proxies"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// DefaultSettings 返回安全默认值：回环监听、托管模式、mixed 入站。
func DefaultSettings() Settings {
	return Settings{
		WebListen:    "127.0.0.1:9090",
		Mode:         "managed",
		ProxyMode:    "rule",
		Whitelist:    []string{},
		ProxyDomains: []string{},
		TUNName:      "sp-tun",
		DNSPreset:    "fakeip",
		MixedPort:    7897,
		UpdatedAt:    time.Now().UTC(),
	}
}

// Subscription 订阅定义（subscriptions 表）。URL 只保存密文。
type Subscription struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	URLCipher    string    `json:"url_ciphertext"`
	Schedule     string    `json:"schedule"` // 每 6 小时 | 每天
	Enabled      bool      `json:"enabled"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	LastStatus   string    `json:"last_status"` // pending | ok | failed
	LastError    string    `json:"last_error,omitempty"`
	LastUpdated  time.Time `json:"last_updated"`
	NodeCount    int       `json:"node_count"`
	Warnings     int       `json:"warnings"`
}

// NodeRecord 保留最近一次成功解析的节点集（nodes 表的文件形态）。
type NodeRecord struct {
	Fingerprint string          `json:"fingerprint"`
	SubID       string          `json:"subscription_id"`
	DisplayName string          `json:"display_name"`
	Type        string          `json:"type"`
	Spec        json.RawMessage `json:"spec_json"`
}

// RuleSetRecord 远程/本地规则集（rule_sets 表）。
type RuleSetRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`   // remote | local
	Format      string `json:"format"` // source | binary
	URL         string `json:"url,omitempty"`
	Interval    string `json:"interval"`
	InitialPath string `json:"initial_path"`
	// LocalPath 表示本地缓存已存在（值为 InitialPath 的相对路径），
	// 编译托管配置时优先使用本地引用，内核启动不再依赖外网。
	LocalPath   string    `json:"local_path,omitempty"`
	Status      string    `json:"status"` // ok | failed | pending
	LastError   string    `json:"last_error,omitempty"`
	ETag        string    `json:"etag,omitempty"`
	Hash        string    `json:"hash,omitempty"`
	LastUpdated time.Time `json:"last_updated"`
}

// RevisionMeta 配置修订索引（config_revisions 表）。
type RevisionMeta struct {
	ID        string    `json:"id"`
	State     string    `json:"state"` // draft | applied | failed | rolled_back
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"` // web | cli | scheduler
	Source    string    `json:"source"`     // editor | subscription-update | restore | seed
	Managed   bool      `json:"managed"`
	Summary   string    `json:"summary"`
	Checksum  string    `json:"checksum"`
	Error     string    `json:"error,omitempty"`
}

// AuditEvent 审计事件（audit_events 表，追加写入 JSONL）。
type AuditEvent struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	IP      string    `json:"ip"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Result  string    `json:"result"`
	TraceID string    `json:"trace_id"`
}

// AppendAudit 追加一条审计记录。
func (r *Root) AppendAudit(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(r.Path("audit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

// LoadAudit 读取最近 limit 条审计事件。
func (r *Root) LoadAudit(limit int) []AuditEvent {
	data, err := os.ReadFile(r.Path("audit.log"))
	if err != nil {
		return nil
	}
	var events []AuditEvent
	for _, line := range splitLines(data) {
		var e AuditEvent
		if json.Unmarshal(line, &e) == nil {
			events = append(events, e)
		}
	}
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				out = append(out, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
