package app

import "fmt"

// SystemdUnit 生成幂等安装所需的 systemd unit（实现方案 §3.2）。
// ExecStartPre 用内核 check 复核最后生效配置；ExecReload 仅在
// 候选配置通过校验后由控制面触发。内核二进制由 install-kernel 安装到
// <dataDir>/bin/sing-box，sp 启动时经 --core singbox 自动探测。
func SystemdUnit(dataDir string) string {
	if dataDir == "" {
		dataDir = "/var/lib/serverproxy"
	}
	return fmt.Sprintf(`# ServerProxy 控制面 systemd unit（由 sp 		install-service 生成）
	# 安装：sudo cp serverproxy.service /etc/systemd/system/ && sudo systemctl daemon-reload

	[Unit]
	Description=ServerProxy control plane (sing-box manager)
	Documentation=https://github.com/sagernet/sing-box
	After=network-online.target
	Wants=network-online.target

	[Service]
	Type=notify
	User=serverproxy
	Group=serverproxy
	ExecStartPre=+/usr/local/bin/sp check %s/runtime/config.json
	ExecStart=/usr/local/bin/sp serve --listen 127.0.0.1:9090 --data-dir %s --core singbox
	ExecReload=/bin/kill -HUP $MAINPID
	Restart=on-failure
	RestartSec=3s
	StartLimitIntervalSec=60
	StartLimitBurst=5

	# 最小能力集：TUN、原始套接字、绑定低端口
	CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
	AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
	NoNewPrivileges=yes
	DeviceAllow=/dev/net/tun rw

	# 文件系统与网络加固
	ProtectSystem=strict
	ReadWritePaths=%s /var/log/serverproxy /run/serverproxy
	ProtectHome=yes
	PrivateTmp=yes
	RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
	ProtectKernelTunables=yes
	ProtectControlGroups=yes
	RestrictSUIDSGID=yes
	LockPersonality=yes
	MemoryDenyWriteExecute=yes

	[Install]
	WantedBy=multi-user.target
`, dataDir, dataDir, dataDir)
}
