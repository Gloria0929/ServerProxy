package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"proxypanel/internal/app"
	"proxypanel/internal/core"
	"proxypanel/internal/kernel"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "status":
		status(os.Args[2:])
	case "switch":
		switchProxy(os.Args[2:])
	case "update":
		postAction(os.Args[2:], "/api/v1/subscriptions/all/update")
	case "reload", "restart":
		postAction(os.Args[2:], "/api/v1/system/restart")
	case "log":
		showLogs(os.Args[2:])
	case "check":
		check(os.Args[2:])
	case "mode":
		switchMode(os.Args[2:])
	case "tun":
		toggleTUN(os.Args[2:])
	case "install-service":
		installService(os.Args[2:])
	case "install-kernel":
		installKernel(os.Args[2:])
	case "version":
		fmt.Println("ServerProxy", version)
	default:
		printUsage()
	}
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "", "HTTP listen address（默认：$SP_LISTEN > settings.web_listen > 127.0.0.1:9090）")
	secret := fs.String("secret", os.Getenv("SP_SECRET"), "web login secret")
	dataDir := fs.String("data-dir", os.Getenv("SP_DATA_DIR"), "runtime data directory")
	coreName := fs.String("core", os.Getenv("SP_CORE"), "core adapter: dev|singbox")
	singBoxBin := fs.String("sing-box-bin", os.Getenv("SP_SINGBOX_BIN"), "path to sing-box binary")
	controller := fs.String("controller", os.Getenv("SP_SINGBOX_CONTROLLER"), "clash api controller (auto if empty)")
	coreSecret := fs.String("core-secret", os.Getenv("SP_SINGBOX_SECRET"), "clash api secret (auto if empty)")
	external := fs.Bool("external-core", os.Getenv("SP_EXTERNAL_CORE") == "1", "assume sing-box managed externally")
	pidFile := fs.String("core-pid", os.Getenv("SP_SINGBOX_PID"), "pid file for external-core SIGHUP")
	resetSecret := fs.Bool("reset-secret", false, "regenerate the web secret and print it once")
	_ = fs.Parse(args)

	if *dataDir == "" {
		*dataDir = filepath.Join(".", ".serverproxy")
	}
	useSingBox := *coreName == "singbox"
	service, err := app.NewService(app.Config{
		Secret:      *secret,
		DataDir:     *dataDir,
		Version:     version,
		ResetSecret: *resetSecret,
		UseSingBox:  useSingBox,
		SingBox: core.SingBoxOptions{
			Binary: *singBoxBin, Controller: *controller, Secret: *coreSecret,
			External: *external, PIDFile: *pidFile,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to initialise ServerProxy:", err)
		os.Exit(1)
	}
	// 监听地址优先级：--listen 参数 > SP_LISTEN 环境变量 > settings.web_listen > 默认回环。
	if *listen == "" {
		*listen = os.Getenv("SP_LISTEN")
	}
	if *listen == "" {
		*listen = service.Settings().WebListen
	}
	if *listen == "" {
		*listen = "127.0.0.1:9090"
	}
	if *secret == "" {
		if generated := service.BootstrapSecret(); generated != "" {
			fmt.Println("已生成网页访问密钥（仅显示这一次）:", generated)
			fmt.Println("请妥善保存；可通过 SP_SECRET 或 --secret 覆盖。")
		} else {
			fmt.Println("已存在网页访问密钥（仅以 Argon2id 哈希保存，无法回显明文）。")
			fmt.Println("如需重设：设置 SP_SECRET / 传 --secret，或加 --reset-secret 重新生成。")
		}
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	go func() {
		if err := service.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "background loop error:", err)
		}
	}()

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           service.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		fmt.Printf("ServerProxy %s is listening on http://%s\n", version, *listen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "server error:", err)
			os.Exit(1)
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	cancelRun()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

func status(args []string) {
	response, err := authedRequest(args, http.MethodGet, "/api/v1/system/status", nil)
	if err != nil {
		exitError(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(os.Stdout, response.Body)
}

func switchProxy(args []string) {
	if len(args) < 2 {
		exitError(fmt.Errorf("usage: sp switch <group> <node> [--endpoint ...] [--secret ...]"))
	}
	payload, _ := json.Marshal(map[string]string{"node_id": args[1]})
	response, err := authedRequest(args[2:], http.MethodPatch, "/api/v1/proxies/groups/"+args[0]+"/selection", payload)
	if err != nil {
		exitError(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(os.Stdout, response.Body)
}

func postAction(args []string, path string) {
	response, err := authedRequest(args, http.MethodPost, path, []byte("{}"))
	if err != nil {
		exitError(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(os.Stdout, response.Body)
}

func showLogs(args []string) {
	response, err := authedRequest(args, http.MethodGet, "/api/v1/logs", nil)
	if err != nil {
		exitError(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(os.Stdout, response.Body)
}

func check(args []string) {
	if len(args) != 1 {
		exitError(fmt.Errorf("usage: sp check <config.json>"))
	}
	contents, err := os.ReadFile(args[0])
	if err != nil {
		exitError(err)
	}
	var document any
	if err := json.Unmarshal(contents, &document); err != nil {
		exitError(fmt.Errorf("invalid JSON: %w", err))
	}
	if _, ok := document.(map[string]any); !ok {
		exitError(fmt.Errorf("configuration root must be a JSON object"))
	}
	fmt.Println("configuration JSON is valid")
}

func installService(args []string) {
	fs := flag.NewFlagSet("install-service", flag.ExitOnError)
	output := fs.String("output", "", "write the unit to a file instead of stdout")
	dataDir := fs.String("data-dir", "/var/lib/serverproxy", "runtime data directory")
	version := fs.String("version", "", "sing-box 内核版本（留空取最新）")
	platform := fs.String("platform", "", "内核平台（留空用当前平台，如 linux-amd64）")
	skipKernel := fs.Bool("skip-kernel", false, "跳过下载 sing-box 内核")
	_ = fs.Parse(args)

	if !*skipKernel {
		fmt.Println("下载 sing-box 内核 ...")
		kernelPath := filepath.Join(*dataDir, "bin", kernel.BinaryName(kernel.CurrentPlatform()))
		path, err := kernel.Install(context.Background(), *version, *platform, kernelPath)
		if err != nil {
			exitError(fmt.Errorf("安装内核失败：%w", err))
		}
		fmt.Printf("内核已安装到 %s\n", path)
	}

	unit := app.SystemdUnit(*dataDir)
	if *output == "" {
		fmt.Print(unit)
		return
	}
	if err := os.WriteFile(*output, []byte(unit), 0o644); err != nil {
		exitError(err)
	}
	fmt.Println("wrote", *output)
}

func switchMode(args []string) {
	if len(args) < 1 {
		exitError(fmt.Errorf("用法: sp mode <rule|global|direct> [--endpoint ...] [--secret ...]"))
	}
	mode := args[0]
	if mode != "rule" && mode != "global" && mode != "direct" {
		exitError(fmt.Errorf("模式必须为 rule、global 或 direct"))
	}
	payload, _ := json.Marshal(map[string]string{"proxy_mode": mode})
	response, err := authedRequest(args[1:], http.MethodPatch, "/api/v1/settings", payload)
	if err != nil {
		exitError(err)
	}
	defer response.Body.Close()
	io.Copy(os.Stdout, response.Body)
	fmt.Println()
}

func toggleTUN(args []string) {
	if len(args) < 1 {
		exitError(fmt.Errorf("用法: sp tun <on|off> [--endpoint ...] [--secret ...]"))
	}
	enabled := false
	switch args[0] {
	case "on":
		enabled = true
	case "off":
		enabled = false
	default:
		exitError(fmt.Errorf("参数必须为 on 或 off"))
	}
	payload, _ := json.Marshal(map[string]bool{"tun_enabled": enabled})
	response, err := authedRequest(args[1:], http.MethodPatch, "/api/v1/settings", payload)
	if err != nil {
		exitError(err)
	}
	defer response.Body.Close()
	io.Copy(os.Stdout, response.Body)
	fmt.Println()
}

func authedRequest(args []string, method, path string, body []byte) (*http.Response, error) {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	endpoint := fs.String("endpoint", "http://127.0.0.1:9090", "ServerProxy endpoint")
	secret := fs.String("secret", os.Getenv("SP_SECRET"), "web login secret")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *secret == "" {
		return nil, fmt.Errorf("set --secret or SP_SECRET")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	loginBody, _ := json.Marshal(map[string]string{"secret": *secret})
	login, err := client.Post(*endpoint+"/api/v1/auth/login", "application/json", stringReader(loginBody))
	if err != nil {
		return nil, err
	}
	defer login.Body.Close()
	if login.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed: %s", login.Status)
	}
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(login.Body).Decode(&session); err != nil {
		return nil, err
	}
	request, err := http.NewRequest(method, *endpoint+path, stringReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", session.CSRFToken)
	for _, cookie := range login.Cookies() {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		contents, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("request failed: %s: %s", response.Status, string(contents))
	}
	return response, nil
}

func stringReader(contents []byte) io.Reader {
	return &byteReader{contents: contents}
}

type byteReader struct{ contents []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.contents) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.contents)
	r.contents = r.contents[n:]
	return n, nil
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, "sp:", err)
	os.Exit(1)
}

func printUsage() {
	fmt.Println(`ServerProxy CLI

Usage:
  sp serve [--listen 127.0.0.1:9090] [--secret ...]
  sp status [--endpoint ...] [--secret ...]
  sp switch <group> <node> [--endpoint ...] [--secret ...]
  sp mode <rule|global|direct> [--endpoint ...] [--secret ...]
  sp tun <on|off> [--endpoint ...] [--secret ...]
  sp update | sp reload | sp restart | sp log
  sp check <config.json>
  sp install-service [--output serverproxy.service]
  sp install-kernel [--version x.y.z] [--platform linux-amd64] [--output ./bin/sing-box]
  sp version`)
}
