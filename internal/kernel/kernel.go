// Package kernel 负责从官方 Release 下载并安装 sing-box 内核二进制。
// sing-box 是 sp 的外部运行时内核（子进程），按平台下载固定版本到项目目录，
// 不编译进 sp、也不提交进仓库。CLI 与 Web API 共用本包的 Install。
package kernel

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const releaseBase = "https://github.com/SagerNet/sing-box/releases"

// Install 下载并安装内核。version/platform/output 为空时智能回退：
// version→最新版本、platform→当前平台、output→bin/<二进制名>。返回落地路径。
func Install(ctx context.Context, version, platform, output string) (string, error) {
	if version == "" {
		v, err := latestVersion(ctx)
		if err != nil {
			return "", fmt.Errorf("获取最新版本失败：%w", err)
		}
		version = v
	}
	if platform == "" {
		platform = CurrentPlatform()
	}
	ext := "tar.gz"
	bin := "sing-box"
	if IsWindows(platform) {
		ext = "zip"
		bin = "sing-box.exe"
	}
	if output == "" {
		output = filepath.Join("bin", bin)
	}

	asset := fmt.Sprintf("sing-box-%s-%s.%s", version, platform, ext)
	base := fmt.Sprintf("%s/download/v%s", releaseBase, version)

	archive, err := download(ctx, base+"/"+asset, 256<<20, 10*time.Minute)
	if err != nil {
		return "", err
	}
	if sum, ok := fetchChecksum(ctx, base+"/checksums.txt", asset); ok {
		if sha256Hex(archive) != sum {
			return "", fmt.Errorf("SHA-256 校验失败：%s（已中止）", asset)
		}
	}
	if err := extract(archive, ext, bin, output); err != nil {
		return "", err
	}
	return output, nil
}

// CurrentPlatform 返回当前 OS/arch 的平台串，如 linux-amd64。
func CurrentPlatform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// IsWindows 判断平台是否为 Windows（用 .zip 压缩包 + .exe 二进制）。
func IsWindows(platform string) bool { return strings.HasPrefix(platform, "windows-") }

// BinaryName 返回平台的 sing-box 二进制文件名。
func BinaryName(platform string) string {
	if IsWindows(platform) {
		return "sing-box.exe"
	}
	return "sing-box"
}

func latestVersion(ctx context.Context) (string, error) {
	body, err := download(ctx, "https://api.github.com/repos/SagerNet/sing-box/releases/latest", 16<<20, 30*time.Second)
	if err != nil {
		return "", err
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", err
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

func download(ctx context.Context, url string, limit int64, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("请求构造失败：%w", err)
	}
	req.Header.Set("User-Agent", "ServerProxy/kernel-installer")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载失败：%s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func fetchChecksum(ctx context.Context, url, asset string) (string, bool) {
	body, err := download(ctx, url, 16<<20, 30*time.Second)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[len(fields)-1] == asset {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func extract(archive []byte, ext, binName, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if ext == "zip" {
		return extractZip(archive, binName, dest)
	}
	return extractTarGz(archive, binName, dest)
}

func extractZip(archive []byte, binName, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("解压 zip 失败：%w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != binName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return writeFile(dest, rc)
	}
	return fmt.Errorf("压缩包中未找到 %s", binName)
}

func extractTarGz(archive []byte, binName, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("解压 tar.gz 失败：%w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == binName {
			return writeFile(dest, io.LimitReader(tr, hdr.Size))
		}
	}
	return fmt.Errorf("压缩包中未找到 %s", binName)
}

func writeFile(dest string, src io.Reader) error {
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("写入 %s 失败：%w", dest, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, src); err != nil {
		return fmt.Errorf("写入 %s 失败：%w", dest, err)
	}
	return nil
}
