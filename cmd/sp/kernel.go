// 内核安装 CLI：sp install-kernel [--version x.y.z] [--platform linux-amd64] [--output ./bin/sing-box]
package main

import (
	"context"
	"flag"
	"fmt"

	"proxypanel/internal/kernel"
)

func installKernel(args []string) {
	fs := flag.NewFlagSet("install-kernel", flag.ExitOnError)
	version := fs.String("version", "", "要安装的版本（如 1.11.0），留空取最新")
	platform := fs.String("platform", "", "目标平台（如 linux-amd64），留空用当前平台")
	output := fs.String("output", "", "输出路径（默认 ./bin/sing-box）")
	_ = fs.Parse(args)

	path, err := kernel.Install(context.Background(), *version, *platform, *output)
	if err != nil {
		exitError(fmt.Errorf("安装内核失败：%w", err))
	}
	fmt.Printf("内核已安装到 %s\n", path)
	fmt.Printf("启动时使用：sp serve --core singbox --sing-box-bin %s\n", path)
}
