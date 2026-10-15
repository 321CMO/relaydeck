package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/321CMO/relaydeck/internal/agent"
	"github.com/321CMO/relaydeck/internal/panel"
	"github.com/321CMO/relaydeck/internal/webassets"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func input() (string, error) {
	b, e := bufio.NewReader(os.Stdin).ReadString('\n')
	if e != nil && b == "" {
		return "", e
	}
	return strings.TrimRight(b, "\r\n"), nil
}
func run() error {
	if len(os.Args) < 2 {
		fmt.Println("RelayDeck " + panel.Version + "\n命令：serve | enroll | agent | setup-code | reset-password | backup | restore | version")
		return nil
	}
	cmd := os.Args[1]
	if cmd == "version" {
		fmt.Println(panel.Version)
		return nil
	}
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	data := f.String("data", "/var/lib/relaydeck/panel", "数据目录")
	dev := f.Bool("dev", false, "仅本机开发时允许 HTTP")
	listen := f.String("listen", "127.0.0.1:8787", "中心监听地址（仅回环地址）")
	base := f.String("url", "", "对外 HTTPS 地址")
	core := f.String("core", "/opt/relaydeck/core/sing-box", "sing-box 可执行文件")
	endpoint := f.String("endpoint", "", "中心地址")
	serverID := f.String("server", "", "服务器 ID")
	adminPort := f.Int("admin-port", 0, "管理 HTTPS 端口；默认随机")
	rotate := f.Bool("rotate", false, "重新生成管理安全路径")
	file := f.String("file", "", "备份文件路径")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("不支持多余参数")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if cmd == "enroll" || cmd == "agent" {
		if *data == "/var/lib/relaydeck/panel" {
			*data = "/var/lib/relaydeck/agent"
		}
		a := agent.New(*data, *core, *dev)
		if cmd == "enroll" {
			if info, e := os.Stat(filepath.Join(*data, "identity.json")); e == nil {
				if !info.Mode().IsRegular() {
					return errors.New("Agent 身份文件无效")
				}
				// Reinstalling an existing Agent must not ask for an expired code.
				// Enroll still verifies endpoint and server ownership before reusing it.
				return a.Enroll(ctx, *endpoint, *serverID, "")
			} else if !os.IsNotExist(e) {
				return e
			}
			fmt.Fprintln(os.Stderr, "输入一次性注册码（不要写入命令行参数）：")
			code, e := input()
			if e != nil {
				return e
			}
			return a.Enroll(ctx, *endpoint, *serverID, code)
		}
		return a.Run(ctx)
	}
	if cmd == "show-entry" {
		b, e := os.ReadFile(filepath.Join(*data, "admin-entry.txt"))
		if e == nil {
			fmt.Print(string(b))
		}
		return e
	}
	s, e := panel.OpenStore(*data)
	if e != nil {
		return e
	}
	defer s.Close()
	a := panel.New(s, *base, *data, *dev, webassets.Files())
	switch cmd {
	case "bootstrap-https":
		if e := a.BootstrapHTTPS(); e != nil {
			return e
		}
		return a.ConfigureAccess(*adminPort, false)
	case "access":
		return a.ConfigureAccess(*adminPort, *rotate)
	case "serve":
		u, e := url.Parse(*base)
		if e != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("请通过 --url 设置完整面板 HTTPS 地址")
		}
		if u.Scheme != "https" && (!*dev || u.Scheme != "http" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1")) {
			return errors.New("生产环境必须使用 HTTPS 地址")
		}
		host, _, e := net.SplitHostPort(*listen)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("中心必须监听本机回环地址，请由 Caddy 提供外部 HTTPS")
		}
		if !*dev {
			if e := a.BootstrapHTTPS(); e != nil {
				return e
			}
			if e := a.ConfigureAccess(0, false); e != nil {
				return e
			}
		}
		if e := a.PrepareRuntime(); e != nil {
			return e
		}
		if s.Read().PasswordHash == "" {
			fmt.Fprintln(os.Stderr, "首次设置码位于："+filepath.Join(*data, "bootstrap.txt")+"（15 分钟有效）")
		}
		httpServer := &http.Server{Addr: *listen, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
		go a.RunBackground(ctx)
		go func() {
			<-ctx.Done()
			shutdown, c := context.WithTimeout(context.Background(), 10*time.Second)
			defer c()
			httpServer.Shutdown(shutdown)
		}()
		fmt.Fprintln(os.Stderr, "RelayDeck 中心已启动，监听 "+*listen)
		if e = httpServer.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			return e
		}
		return nil
	case "setup-code":
		_, e := a.NewSetupToken()
		if e == nil {
			fmt.Println("已生成新设置码，请读取 " + filepath.Join(*data, "bootstrap.txt"))
		}
		return e
	case "reset-password":
		fmt.Fprintln(os.Stderr, "输入新密码（至少 12 位）；重置前请停止中心服务：")
		password, e := input()
		if e != nil {
			return e
		}
		return a.ResetPassword(password)
	case "backup":
		if *file == "" {
			return errors.New("请通过 --file 指定备份路径")
		}
		fmt.Fprintln(os.Stderr, "输入备份加密口令（至少 12 位）：")
		pass, e := input()
		if e != nil {
			return e
		}
		b, e := s.Export(pass)
		if e != nil {
			return e
		}
		return os.WriteFile(*file, b, 0600)
	case "restore":
		if *file == "" {
			return errors.New("请指定备份文件")
		}
		fmt.Fprintln(os.Stderr, "输入备份口令；恢复前请停止中心服务：")
		pass, e := input()
		if e != nil {
			return e
		}
		b, e := os.ReadFile(*file)
		if e != nil {
			return e
		}
		return s.Import(b, pass)
	default:
		return errors.New("未知命令：" + cmd)
	}
}
