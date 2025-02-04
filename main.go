package ipblocker

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	// 注册模块
	caddy.RegisterModule(IPBlocker{})
	// 注册 Caddyfile 指令
	httpcaddyfile.RegisterHandlerDirective("ipblocker", parseCaddyfile)
}

// IPBlocker 是一个 Caddy HTTP 中间件模块，用于拦截特定 IP。
type IPBlocker struct {
	// JSON 文件的 URL，包含需要拦截的 IP 列表
	BlockListURL string `json:"block_list_url,omitempty"`

	// 刷新 IP 列表的时间间隔
	RefreshInterval string `json:"refresh_interval,omitempty"`

	blockedIPs map[string]struct{}
	mu         sync.RWMutex
	stopChan   chan struct{}
}

// CaddyModule 返回模块信息。
func (IPBlocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ipblocker",
		New: func() caddy.Module { return new(IPBlocker) },
	}
}

// Provision 初始化模块。
func (m *IPBlocker) Provision(ctx caddy.Context) error {
	if m.BlockListURL == "" {
		return errors.New("block_list_url is required")
	}

	if m.RefreshInterval == "" {
		m.RefreshInterval = "5m" // 默认刷新间隔为 5 分钟
	}

	interval, err := time.ParseDuration(m.RefreshInterval)
	if err != nil {
		return err
	}

	m.blockedIPs = make(map[string]struct{})
	m.stopChan = make(chan struct{})

	// 启动后台任务定期刷新 IP 列表
	go m.startRefreshingBlockList(interval)

	return nil
}

// Validate 验证模块配置。
func (m *IPBlocker) Validate() error {
	if m.BlockListURL == "" {
		return errors.New("block_list_url is required")
	}
	return nil
}

// ServeHTTP 拦截请求并检查客户端 IP。
func (m *IPBlocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}

	m.mu.RLock()
	_, blocked := m.blockedIPs[clientIP]
	m.mu.RUnlock()

	if blocked {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Your IP is blocked"))
		return nil
	}

	return next.ServeHTTP(w, r)
}

// Cleanup 停止后台刷新任务。
func (m *IPBlocker) Cleanup() error {
	close(m.stopChan)
	return nil
}

// startRefreshingBlockList 定期从 URL 拉取 IP 列表。
func (m *IPBlocker) startRefreshingBlockList(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.refreshBlockList()
		}
	}
}

// refreshBlockList 从指定的 URL 拉取并解析 IP 列表。
func (m *IPBlocker) refreshBlockList() error {
	resp, err := http.Get(m.BlockListURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to fetch block list: " + resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var ipList []string
	err = json.Unmarshal(body, &ipList)
	if err != nil {
		return err
	}

	newBlockedIPs := make(map[string]struct{})
	for _, ip := range ipList {
		newBlockedIPs[ip] = struct{}{}
	}

	m.mu.Lock()
	m.blockedIPs = newBlockedIPs
	m.mu.Unlock()

	return nil
}

// parseCaddyfile 解析 Caddyfile 配置。
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m IPBlocker
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// UnmarshalCaddyfile 从 Caddyfile 中解析模块配置。
func (m *IPBlocker) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "block_list_url":
				if !d.Args(&m.BlockListURL) {
					return d.ArgErr()
				}
			case "refresh_interval":
				if !d.Args(&m.RefreshInterval) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// 确保接口实现正确
var (
	_ caddy.Provisioner           = (*IPBlocker)(nil)
	_ caddy.Validator             = (*IPBlocker)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPBlocker)(nil)
	_ caddyfile.Unmarshaler       = (*IPBlocker)(nil)
)
