package subscription

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseURIList(t *testing.T) {
	payload := strings.Join([]string{
		"trojan://pass123@example.com:443?sni=cdn.example.com&type=ws&path=%2Fws#香港 01",
		"vless://uuid-abc@1.2.3.4:8443?security=reality&pbk=pubkey&sid=abcd&fp=chrome&sni=www.apple.com#日本 02",
		"hysteria2://pw@5.6.7.8:36712?sni=h2.example.com#美国 05",
		"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@9.9.9.9:8388#台湾 04",
		"socks://user:pw@10.0.0.1:1080#socks节点",
		"https://ignored.example.com/not-a-node", // http(s) 也是白名单协议
		"bogus://x",                              // 白名单外 → warning
	}, "\n")
	result, err := ParsePayload([]byte(payload))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if result.Format != "uri" {
		t.Errorf("format = %q, want uri", result.Format)
	}
	if len(result.Nodes) != 6 {
		t.Fatalf("nodes = %d, want 6", len(result.Nodes))
	}
	first := result.Nodes[0]
	if first.Type != "trojan" || first.DisplayName != "香港 01" {
		t.Errorf("first node = %+v", first)
	}
	warnFound := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "不支持的协议") {
			warnFound = true
		}
	}
	if !warnFound {
		t.Errorf("expected unsupported-protocol warning, got %v", result.Warnings)
	}
}

func TestParseBase64List(t *testing.T) {
	raw := "trojan://pw@example.com:443?sni=a.com#n1\nss://YWVzLTI1Ni1nY206cA@1.1.1.1:8388#n2"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	result, err := ParsePayload([]byte(encoded))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if result.Format != "base64" || len(result.Nodes) != 2 {
		t.Fatalf("format=%s nodes=%d", result.Format, len(result.Nodes))
	}
}

func TestParseVMess(t *testing.T) {
	json := `{"add":"vm.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","ps":"vmess节点","net":"ws","host":"cdn.com","path":"/v","tls":"tls","aid":0,"scy":"auto"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(json))
	result, err := ParsePayload([]byte("vmess://" + encoded))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	node := result.Nodes[0]
	if node.Type != "vmess" || node.DisplayName != "vmess节点" {
		t.Fatalf("node = %+v", node)
	}
	spec := string(node.Spec)
	for _, want := range []string{`"server_port":443`, `"transport"`, `"tls"`} {
		if !strings.Contains(spec, want) {
			t.Errorf("spec missing %s: %s", want, spec)
		}
	}
}

func TestParseClashYAML(t *testing.T) {
	yamlPayload := `
proxies:
  - name: "香港 IEPL"
    type: trojan
    server: hk.example.com
    port: 443
    password: secret
    sni: hk.example.com
    skip-cert-verify: true
    udp: true
  - name: "广告机"
    type: ss
    server: 2.2.2.2
    port: 8388
    cipher: aes-256-gcm
    password: pw2
`
	result, err := ParsePayload([]byte(yamlPayload))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(result.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(result.Nodes))
	}
	if result.Nodes[0].Type != "trojan" {
		t.Errorf("type = %s", result.Nodes[0].Type)
	}
	if len(result.Warnings) == 0 {
		t.Errorf("skip-cert-verify 应产生警告")
	}
	spec := string(result.Nodes[0].Spec)
	if !strings.Contains(spec, `"insecure":true`) {
		t.Errorf("insecure 未映射: %s", spec)
	}
}

func TestFingerprintDedup(t *testing.T) {
	line := "trojan://pw@same.com:443#node-a\ntrojan://pw@same.com:443#node-b"
	result, err := ParsePayload([]byte(line))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(result.Nodes) != 1 {
		t.Fatalf("重复节点未合并: %d", len(result.Nodes))
	}
}

func TestSSRFBlockedRanges(t *testing.T) {
	// isBlockedIP 的边界校验。
	if !isBlockedIP(net.ParseIP("127.0.0.1")) || !isBlockedIP(net.ParseIP("192.168.1.1")) ||
		!isBlockedIP(net.ParseIP("169.254.1.1")) || !isBlockedIP(net.ParseIP("10.0.0.2")) ||
		!isBlockedIP(net.ParseIP("fd00::1")) {
		t.Error("内网/环回地址应被拦截")
	}
	if isBlockedIP(net.ParseIP("93.184.216.34")) || isBlockedIP(net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")) {
		t.Error("公网地址不应被拦截")
	}
}

func TestScheduleIntervalFloor(t *testing.T) {
	if ScheduleInterval("每小时") != 6*time.Hour { // 最短 6 小时（实现方案 §5.3）
		t.Error("每小时应被提升到 6 小时下限")
	}
	if ScheduleInterval("每天") != 24*time.Hour {
		t.Error("每天应映射为 24 小时")
	}
}
