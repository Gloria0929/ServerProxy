package app

import "fmt"

// SystemdUnit 生成 systemd unit（实现方案 §3.2）。
// 约定（与生成器行为强相关，勿随意改动）：
//   - 面板未实现 sd_notify，因此 Type=simple；
//   - 以 root 运行（TUN 需要），不依赖预创建的 serverproxy 用户；
//   - ExecStartPre 的 `-` 前缀表示失败不阻塞启动：全新数据目录尚无
//     runtime/config.json，首次启动由面板自行播种托管配置；
//   - 不启用 systemd 沙箱强化（ProtectSystem / RestrictAddressFamilies 等）：
//     子进程 sing-box 需要 netlink 探测网卡与路由、需要写 /tmp 等，
//     沙箱会直接导致内核启动失败（RestrictAddressFamilies 阻断 AF_NETLINK 等）；
//     需要时请按机器环境逐条验证后再启用；
//   - 内核二进制位于 <dataDir>/bin/sing-box（install-service /
//     install-kernel 下载），sp 经 --core singbox 自动探测。
func SystemdUnit(dataDir string) string {
	if dataDir == "" {
		dataDir = "/var/lib/serverproxy"
	}
	// 注意：unit 内容必须顶格书写（systemd 对行首空白无官方保证，
	// 行首制表符会导致 “Assignment outside of section”）。
	return fmt.Sprintf(`# ServerProxy control plane (sing-box manager)
# 安装：sudo cp serverproxy.service /etc/systemd/system/ && sudo systemctl daemon-reload

[Unit]
Description=ServerProxy control plane (sing-box manager)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/usr/local/bin/sp check %[1]s/runtime/config.json
ExecStart=/usr/local/bin/sp serve --listen 127.0.0.1:9090 --data-dir %[1]s --core singbox
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3s
StartLimitIntervalSec=60
StartLimitBurst=5

# 可选加固（按需逐条验证后启用；RestrictAddressFamilies 会阻断 sing-box
# 的 netlink 接口探测，ProtectSystem 需同时放行数据目录与 /tmp）：
# CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
# AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
# NoNewPrivileges=yes
# DeviceAllow=/dev/net/tun rw

[Install]
WantedBy=multi-user.target
`, dataDir)
}