// 订阅内容解析：支持单节点 URI、Base64 URI 列表、Clash YAML/JSON。
// 协议范围与《实现方案》§5.3 的白名单一致：SS、VMess、VLESS、Trojan、
// Hysteria2、TUIC、AnyTLS、SOCKS、HTTP。无法映射的字段进入 warnings，
// 不允许静默丢失。
package subscription

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"proxypanel/internal/store"
)

// ParseResult 一次解析的产物。
type ParseResult struct {
	Format   string             `json:"format"` // uri | base64 | clash-yaml | clash-json
	Nodes    []store.NodeRecord `json:"nodes"`
	Warnings []string           `json:"warnings"`
}

// ParsePayload 识别格式并解析为标准化节点。
func ParsePayload(data []byte) (*ParseResult, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("订阅内容为空")
	}
	// Clash JSON：根对象含 proxies 数组。
	if strings.HasPrefix(trimmed, "{") {
		var doc struct {
			Proxies []map[string]any `json:"proxies"`
		}
		if err := json.Unmarshal(data, &doc); err == nil && len(doc.Proxies) > 0 {
			return parseClashProxies(doc.Proxies, "clash-json")
		}
		return nil, fmt.Errorf("无法识别的 JSON 订阅格式（缺少 proxies 数组）")
	}
	// Clash YAML。
	if strings.ContainsAny(trimmed, "\n") && strings.Contains(trimmed, "proxies:") {
		var doc struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(data, &doc); err == nil && len(doc.Proxies) > 0 {
			return parseClashProxies(doc.Proxies, "clash-yaml")
		}
	}
	// Base64 包裹的 URI 列表。
	if !strings.Contains(trimmed, "://") {
		if decoded, err := base64.StdEncoding.DecodeString(padBase64(trimmed)); err == nil && strings.Contains(string(decoded), "://") {
			return parseURIList(string(decoded), "base64")
		}
		if decoded, err := base64.URLEncoding.DecodeString(padBase64(trimmed)); err == nil && strings.Contains(string(decoded), "://") {
			return parseURIList(string(decoded), "base64")
		}
		return nil, fmt.Errorf("无法识别的订阅格式")
	}
	return parseURIList(trimmed, "uri")
}

func padBase64(s string) string {
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

func parseURIList(content, format string) (*ParseResult, error) {
	result := &ParseResult{Format: format}
	seen := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		node, warn, err := ParseURI(line)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("第 %d 行无法解析：%v", len(result.Nodes)+len(result.Warnings)+1, err))
			continue
		}
		result.Warnings = append(result.Warnings, warn...)
		if seen[node.Fingerprint] {
			result.Warnings = append(result.Warnings, fmt.Sprintf("重复节点已合并：%s", node.DisplayName))
			continue
		}
		seen[node.Fingerprint] = true
		result.Nodes = append(result.Nodes, *node)
	}
	if len(result.Nodes) == 0 {
		return nil, fmt.Errorf("订阅中未解析出任何节点")
	}
	return result, nil
}

// ParseURI 解析单个分享链接。
func ParseURI(raw string) (*store.NodeRecord, []string, error) {
	scheme, _, _ := strings.Cut(raw, "://")
	switch scheme {
	case "ss":
		return parseSS(raw)
	case "vmess":
		return parseVMess(raw)
	case "vless", "trojan", "hysteria2", "hy2", "tuic", "anytls", "socks", "socks5", "http", "https":
		return parseGenericURL(raw)
	default:
		return nil, nil, fmt.Errorf("不支持的协议 %q（白名单外）", scheme)
	}
}

// fingerprintSpec 用完整 spec（含传输/TLS/REALITY 等所有区分字段）生成指纹，
// 避免误合并仅服务器、端口、身份相同但路径/传输不同的节点。
func fingerprintSpec(spec map[string]any) string {
	raw, err := json.Marshal(spec) // encoding/json 对 map key 排序，结果确定
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// regionGuess 从节点名猜测地区，用于展示。
var regionPatterns = []struct {
	pattern *regexp.Regexp
	region  string
}{
	{regexp.MustCompile(`(?i)香港|HK|Hong ?Kong|港`), "香港"},
	{regexp.MustCompile(`(?i)台湾|TW|Taiwan|台`), "台湾"},
	{regexp.MustCompile(`(?i)日本|JP|Japan|东京|大阪`), "日本"},
	{regexp.MustCompile(`(?i)新加坡|SG|Singapore|狮城`), "新加坡"},
	{regexp.MustCompile(`(?i)美国|US|USA|United ?States|洛杉矶|圣何塞|西雅图`), "美国"},
	{regexp.MustCompile(`(?i)韩国|KR|Korea|首尔`), "韩国"},
	{regexp.MustCompile(`(?i)英国|UK|GB|London`), "英国"},
	{regexp.MustCompile(`(?i)德国|DE|Germany|法兰克福`), "德国"},
}

func guessRegion(name string) string {
	for _, p := range regionPatterns {
		if p.pattern.MatchString(name) {
			return p.region
		}
	}
	return "其他"
}

// parseSS 解析 SIP002 shadowsocks 链接。
func parseSS(raw string) (*store.NodeRecord, []string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	var method, password string
	if u.User != nil {
		// userinfo 可能是 base64(method:password)。
		info, decErr := base64.RawURLEncoding.DecodeString(u.User.String())
		if decErr == nil && strings.Contains(string(info), ":") {
			method, password, _ = strings.Cut(string(info), ":")
		} else {
			method = u.User.Username()
			password, _ = u.User.Password()
		}
	} else {
		hostPart, _, _ := strings.Cut(strings.TrimPrefix(raw, "ss://"), "/")
		decoded, decErr := base64.RawURLEncoding.DecodeString(hostPart)
		if decErr != nil {
			return nil, nil, fmt.Errorf("ss 节点缺少凭据")
		}
		method, password, _ = strings.Cut(string(decoded), ":")
		hostPart = string(decoded)
		_ = hostPart
		// 重新按 method:password@host:port 解析。
		return parseSSLegacy(string(decoded), u)
	}
	if method == "" || password == "" {
		return nil, nil, fmt.Errorf("ss 节点缺少加密方式或密码")
	}
	name, _ := url.QueryUnescape(u.Fragment)
	spec := map[string]any{
		"type": "shadowsocks", "server": u.Hostname(), "server_port": port(u, 443),
		"method": method, "password": password,
	}
	warns := pluginWarnings(u)
	return buildNode("shadowsocks", name, u.Hostname(), spec, warns), warns, nil
}

func parseSSLegacy(decoded string, u *url.URL) (*store.NodeRecord, []string, error) {
	userInfo, hostPort, _ := strings.Cut(decoded, "@")
	method, password, _ := strings.Cut(userInfo, ":")
	host, portStr, _ := strings.Cut(hostPort, ":")
	portNum, err := strconv.Atoi(portStr)
	if err != nil || method == "" || password == "" {
		return nil, nil, fmt.Errorf("ss 节点格式不完整")
	}
	name, _ := url.QueryUnescape(u.Fragment)
	spec := map[string]any{"type": "shadowsocks", "server": host, "server_port": portNum, "method": method, "password": password}
	return buildNode("shadowsocks", name, host, spec, nil), nil, nil
}

// parseVMess 解析 base64 JSON 的 v2rayN 分享链接。
func parseVMess(raw string) (*store.NodeRecord, []string, error) {
	payload := strings.TrimPrefix(raw, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(padBase64(payload))
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(payload, "="))
		if err != nil {
			return nil, nil, fmt.Errorf("vmess 节点 base64 解码失败")
		}
	}
	var doc struct {
		Add     string `json:"add"`
		Port    any    `json:"port"`
		ID      string `json:"id"`
		Ps      string `json:"ps"`
		Net     string `json:"net"`
		Host    string `json:"host"`
		Path    string `json:"path"`
		TLS     string `json:"tls"`
		SNI     string `json:"sni"`
		AlterID any    `json:"aid"`
		Scy     string `json:"scy"`
	}
	if err := json.Unmarshal(decoded, &doc); err != nil {
		return nil, nil, fmt.Errorf("vmess 节点 JSON 无效")
	}
	if doc.Add == "" || doc.ID == "" {
		return nil, nil, fmt.Errorf("vmess 节点缺少地址或 UUID")
	}
	port := toInt(doc.Port)
	security := doc.Scy
	if security == "" {
		security = "auto"
	}
	spec := map[string]any{
		"type": "vmess", "server": doc.Add, "server_port": port,
		"uuid": doc.ID, "alter_id": toInt(doc.AlterID), "security": security,
	}
	var warns []string
	if doc.Net == "ws" {
		spec["transport"] = map[string]any{"type": "ws", "path": doc.Path, "headers": map[string]any{"Host": doc.Host}}
	} else if doc.Net != "" && doc.Net != "tcp" {
		warns = append(warns, fmt.Sprintf("vmess 传输层 %q 已映射为基础参数，细节字段需手工核对", doc.Net))
	}
	if doc.TLS == "tls" {
		spec["tls"] = map[string]any{"enabled": true, "server_name": firstNonEmpty(doc.SNI, doc.Host, doc.Add)}
	}
	return buildNode("vmess", doc.Ps, doc.Add, spec, warns), warns, nil
}

// parseGenericURL 解析 vless/trojan/hysteria2/tuic/anytls/socks/http 分享链接。
func parseGenericURL(raw string) (*store.NodeRecord, []string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "hy2" {
		scheme = "hysteria2"
	}
	if scheme == "socks5" {
		scheme = "socks"
	}
	typeName := scheme
	switch scheme {
	case "vless", "trojan":
		typeName = scheme
	case "hysteria2":
		typeName = "hysteria2"
	case "tuic":
		typeName = "tuic"
	case "anytls":
		typeName = "anytls"
	case "socks":
		typeName = "socks"
	case "http", "https":
		typeName = "http"
	}
	port := port(u, 443)
	spec := map[string]any{"type": typeName, "server": u.Hostname(), "server_port": port}

	var warns []string
	password, _ := u.User.Password()
	username := u.User.Username()
	switch typeName {
	case "vless":
		if username == "" {
			return nil, nil, fmt.Errorf("vless 节点缺少 UUID")
		}
		spec["uuid"] = username
		if flow := u.Query().Get("flow"); flow != "" {
			spec["flow"] = flow
		}
	case "trojan", "hysteria2", "anytls":
		// 常见订阅里 trojan://password@host 形链接把密码直接放在 userinfo 的用户名位，
		// url 包解析后 Password() 为空——此时回落到 Username 作为密码。
		if password == "" {
			password = username
		}
		if password == "" {
			return nil, nil, fmt.Errorf("%s 节点缺少密码", typeName)
		}
		spec["password"] = password
	case "tuic":
		spec["uuid"] = username
		if password != "" {
			spec["password"] = password
		}
		if cc := u.Query().Get("congestion_control"); cc != "" {
			spec["congestion_control"] = cc
		}
	case "socks":
		spec["version"] = "5"
		if username != "" {
			spec["username"] = username
		}
		if password != "" {
			spec["password"] = password
		}
	case "http":
		if scheme == "https" || u.Query().Get("security") == "tls" {
			spec["tls"] = map[string]any{"enabled": true}
		}
		if username != "" {
			spec["username"] = username
		}
		if password != "" {
			spec["password"] = password
		}
	}

	q := u.Query()
	// TLS / REALITY 参数映射。
	needTLS := scheme != "socks" && scheme != "http" ||
		(scheme == "http" && q.Get("security") == "tls")
	if needTLS && (q.Get("security") == "tls" || q.Get("security") == "reality" || scheme == "trojan" || scheme == "hysteria2" || scheme == "tuic" || scheme == "anytls" || (scheme == "vless" && q.Get("security") != "none")) {
		tls := map[string]any{"enabled": true}
		if sni := q.Get("sni"); sni != "" {
			tls["server_name"] = sni
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			tls["insecure"] = true
			warns = append(warns, "节点启用了 allowInsecure，生产环境不建议")
		}
		if q.Get("security") == "reality" {
			reality := map[string]any{"enabled": true}
			if pbk := q.Get("pbk"); pbk != "" {
				reality["public_key"] = pbk
			}
			if sid := q.Get("sid"); sid != "" {
				reality["short_id"] = sid
			}
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": q.Get("fp")}
			tls["reality"] = reality
		}
		spec["tls"] = tls
	}
	// 传输层。
	if net := q.Get("type"); net != "" && net != "tcp" {
		switch net {
		case "ws":
			ws := map[string]any{"type": "ws"}
			if p := q.Get("path"); p != "" {
				ws["path"] = p
			}
			if h := q.Get("host"); h != "" {
				ws["headers"] = map[string]any{"Host": h}
			}
			spec["transport"] = ws
		case "grpc":
			spec["transport"] = map[string]any{"type": "grpc", "service_name": q.Get("serviceName")}
		default:
			warns = append(warns, fmt.Sprintf("传输层 %q 未在白名单内，已忽略", net))
		}
	}
	// 未映射参数收集，写入转换报告。
	known := map[string]bool{"security": true, "sni": true, "allowInsecure": true, "insecure": true, "pbk": true, "sid": true, "fp": true, "type": true, "path": true, "host": true, "serviceName": true, "flow": true, "congestion_control": true, "alpn": true}
	for key := range q {
		if !known[key] {
			warns = append(warns, fmt.Sprintf("查询参数 %s=%s 未映射，已忽略", key, q.Get(key)))
		}
	}
	name, _ := url.QueryUnescape(u.Fragment)
	return buildNode(typeName, name, u.Hostname(), spec, warns), warns, nil
}

func pluginWarnings(u *url.URL) []string {
	var warns []string
	if p := u.Query().Get("plugin"); p != "" {
		warns = append(warns, "ss 插件参数未映射，需要手工处理："+p)
	}
	return warns
}

// parseClashProxies 映射 Clash 代理数组。
func parseClashProxies(proxies []map[string]any, format string) (*ParseResult, error) {
	result := &ParseResult{Format: format}
	seen := map[string]bool{}
	for i, proxy := range proxies {
		// 跳过机场塞进 proxies 的非节点信息行（如“剩余流量/套餐到期”，
		// 其特征是 server 为私网占位地址）。
		if name, _ := proxy["name"].(string); isPlaceholderServer(fmt.Sprint(proxy["server"])) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("跳过非节点信息行：%s", name))
			continue
		}
		node, warns, err := parseClashProxy(proxy)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("proxies[%d] 无法解析：%v", i, err))
			continue
		}
		result.Warnings = append(result.Warnings, warns...)
		if seen[node.Fingerprint] {
			result.Warnings = append(result.Warnings, fmt.Sprintf("重复节点已合并：%s", node.DisplayName))
			continue
		}
		seen[node.Fingerprint] = true
		result.Nodes = append(result.Nodes, *node)
	}
	if len(result.Nodes) == 0 {
		return nil, fmt.Errorf("Clash 配置中未解析出任何节点")
	}
	return result, nil
}

// isPlaceholderServer 判断 server 是否为私网/回环占位地址（机场信息行的特征）。
func isPlaceholderServer(server string) bool {
	ip := net.ParseIP(strings.TrimSpace(server))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func parseClashProxy(p map[string]any) (*store.NodeRecord, []string, error) {
	csType, _ := p["type"].(string)
	name, _ := p["name"].(string)
	server, _ := p["server"].(string)
	port := toInt(p["port"])
	if server == "" || port == 0 {
		return nil, nil, fmt.Errorf("缺少 server/port")
	}
	var warns []string
	spec := map[string]any{"server": server, "server_port": port}
	switch csType {
	case "ss":
		spec["type"] = "shadowsocks"
		spec["method"], _ = p["cipher"].(string)
		spec["password"], _ = p["password"].(string)
		if plugin, ok := p["plugin"].(string); ok && plugin != "" {
			warns = append(warns, fmt.Sprintf("节点 %q 的 ss 插件 %q 需手工处理", name, plugin))
		}
	case "vmess":
		spec["type"] = "vmess"
		spec["uuid"], _ = p["uuid"].(string)
		spec["alter_id"] = toInt(p["alterId"])
		spec["security"], _ = p["cipher"].(string)
		if spec["security"] == "" {
			spec["security"] = "auto"
		}
	case "vless":
		spec["type"] = "vless"
		spec["uuid"], _ = p["uuid"].(string)
		if flow, ok := p["flow"].(string); ok {
			spec["flow"] = flow
		}
	case "trojan":
		spec["type"] = "trojan"
		spec["password"], _ = p["password"].(string)
	case "hysteria2":
		spec["type"] = "hysteria2"
		spec["password"], _ = p["password"].(string)
		if v := toInt(p["up"]); v > 0 {
			spec["up_mbps"] = v
		}
		if v := toInt(p["down"]); v > 0 {
			spec["down_mbps"] = v
		}
	case "tuic":
		spec["type"] = "tuic"
		spec["uuid"], _ = p["uuid"].(string)
		spec["password"], _ = p["password"].(string)
		if cc, ok := p["congestion-controller"].(string); ok {
			spec["congestion_control"] = cc
		}
	case "anytls":
		spec["type"] = "anytls"
		spec["password"], _ = p["password"].(string)
	case "socks5":
		spec["type"] = "socks"
		spec["version"] = "5"
		if v, ok := p["username"].(string); ok {
			spec["username"] = v
		}
		if v, ok := p["password"].(string); ok {
			spec["password"] = v
		}
	case "http":
		spec["type"] = "http"
		if v, ok := p["username"].(string); ok {
			spec["username"] = v
		}
		if v, ok := p["password"].(string); ok {
			spec["password"] = v
		}
		if tls, ok := p["tls"].(bool); ok && tls {
			spec["tls"] = map[string]any{"enabled": true}
		}
	default:
		return nil, nil, fmt.Errorf("Clash 类型 %q 不在支持矩阵内", csType)
	}

	// 通用 TLS / transport 映射。
	if tls, ok := p["tls"].(bool); ok && tls && spec["tls"] == nil {
		spec["tls"] = map[string]any{"enabled": true}
	}
	if sni, ok := p["sni"].(string); ok && sni != "" {
		tlsMap, _ := spec["tls"].(map[string]any)
		if tlsMap == nil {
			tlsMap = map[string]any{"enabled": true}
			spec["tls"] = tlsMap
		}
		tlsMap["server_name"] = sni
	}
	if skip, ok := p["skip-cert-verify"].(bool); ok && skip {
		tlsMap, _ := spec["tls"].(map[string]any)
		if tlsMap == nil {
			tlsMap = map[string]any{"enabled": true}
			spec["tls"] = tlsMap
		}
		tlsMap["insecure"] = true
		warns = append(warns, fmt.Sprintf("节点 %q 启用了 skip-cert-verify", name))
	}
	if wsOpts, ok := p["ws-opts"].(map[string]any); ok {
		ws := map[string]any{"type": "ws"}
		if path, ok := wsOpts["path"].(string); ok {
			ws["path"] = path
		}
		if headers, ok := wsOpts["headers"].(map[string]any); ok {
			ws["headers"] = headers
		}
		spec["transport"] = ws
	}
	for _, key := range []string{"udp", "alpn", "client-fingerprint", "smux", "obfs", "up", "down", "skip-cert-verify"} {
		if _, ok := p[key]; ok && key != "skip-cert-verify" {
			warns = append(warns, fmt.Sprintf("节点 %q 的字段 %s 已按能力表尽力映射，请核对", name, key))
			break
		}
	}
	return buildNode(spec["type"].(string), name, server, spec, warns), warns, nil
}

func buildNode(typeName, name, server string, spec map[string]any, warns []string) *store.NodeRecord {
	if name == "" {
		name = server
	}
	fp := fingerprintSpec(spec)
	spec["tag"] = "sub-" + fp[:8]
	raw, _ := json.Marshal(spec)
	return &store.NodeRecord{
		Fingerprint: fp,
		DisplayName: name,
		Type:        typeName,
		SubID:       "",
		Spec:        raw,
	}
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		num, _ := strconv.Atoi(strings.TrimSpace(n))
		return num
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func port(u *url.URL, fallback int) int {
	if p := u.Port(); p != "" {
		num, err := strconv.Atoi(p)
		if err == nil {
			return num
		}
	}
	return fallback
}
