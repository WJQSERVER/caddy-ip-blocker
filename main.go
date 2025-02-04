package ipblocker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(IPBlocker{})
	httpcaddyfile.RegisterHandlerDirective("ipblocker", parseCaddyfile)
}

// IPBlocker 是插件的主要结构体，负责管理 IP 阻止逻辑
type IPBlocker struct {
	BlockListURL    string   `json:"block_list_url,omitempty"`    // 阻止列表的 URL
	RefreshInterval string   `json:"refresh_interval,omitempty"` // 刷新阻止列表的间隔时间
	TrustProxy      bool     `json:"trust_proxy,omitempty"`      // 是否信任代理头
	SourceHeaders   []string `json:"source_headers,omitempty"`   // 自定义来源标头列表

	blockedIPNets []*net.IPNet // 存储阻止的 IP 网段
	mu            sync.RWMutex // 读写锁，用于保护阻止列表的并发访问
	stopChan      chan struct{} // 用于停止阻止列表刷新协程
	logger        *zap.Logger   // 日志记录器
}

// CaddyModule 返回模块的信息
func (IPBlocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ipblocker",
		New: func() caddy.Module { return new(IPBlocker) },
	}
}

// Provision 初始化模块，设置默认值并启动阻止列表刷新协程
func (m *IPBlocker) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	// 确保 block_list_url 被配置
	if m.BlockListURL == "" {
		return errors.New("block_list_url is required")
	}

	// 设置默认的刷新间隔
	if m.RefreshInterval == "" {
		m.RefreshInterval = "5m"
	}
	interval, err := time.ParseDuration(m.RefreshInterval)
	if err != nil {
		return fmt.Errorf("invalid refresh_interval: %v", err)
	}

	m.blockedIPNets = make([]*net.IPNet, 0)
	m.stopChan = make(chan struct{})

	// 启动阻止列表刷新协程
	go m.startRefreshingBlockList(interval)
	m.logger.Info("IPBlocker provisioned",
		zap.Bool("trust_proxy", m.TrustProxy),
		zap.String("refresh_interval", interval.String()),
		zap.Strings("source_headers", m.SourceHeaders),
	)
	return nil
}

// Validate 校验模块配置是否合法
func (m *IPBlocker) Validate() error {
	if m.BlockListURL == "" {
		return errors.New("block_list_url is required")
	}
	return nil
}

// ServeHTTP 是插件的核心方法，用于处理 HTTP 请求
func (m *IPBlocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP, err := m.getClientIP(r)
	if err != nil {
		m.logger.Error("failed to get client IP", zap.Error(err))
		return caddyhttp.Error(http.StatusForbidden, errors.New("invalid client address"))
	}

	// 检查 IP 是否被阻止
	m.mu.RLock()
	blocked := m.isBlocked(clientIP)
	m.mu.RUnlock()

	if blocked {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Your IP is blocked"))
		return nil
	}

	// 如果未被阻止，则继续处理下一个中间件
	return next.ServeHTTP(w, r)
}

// Cleanup 在模块停止时清理资源
func (m *IPBlocker) Cleanup() error {
	close(m.stopChan)
	return nil
}

// startRefreshingBlockList 周期性刷新阻止列表
func (m *IPBlocker) startRefreshingBlockList(interval time.Duration) {
	// 初次刷新
	if err := m.refreshBlockList(); err != nil {
		m.logger.Error("initial blocklist refresh failed", zap.Error(err))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			if err := m.refreshBlockList(); err != nil {
				m.logger.Error("periodic blocklist refresh failed", zap.Error(err))
			}
		}
	}
}

// getClientIP 获取客户端的 IP 地址
func (m *IPBlocker) getClientIP(r *http.Request) (net.IP, error) {
	var ipStr string

	// 如果信任代理头，则尝试从自定义来源标头中获取 IP
	if m.TrustProxy && len(m.SourceHeaders) > 0 {
		for _, header := range m.SourceHeaders {
			if value := r.Header.Get(header); value != "" {
				ips := strings.Split(value, ",")
				if len(ips) > 0 {
					ipStr = strings.TrimSpace(ips[0])
					break
				}
			}
		}
	}

	// 如果未从自定义来源标头中获取到 IP，则尝试从 RemoteAddr 中获取
	if ipStr == "" {
		var err error
		ipStr, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return nil, fmt.Errorf("splitting remote address: %w", err)
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP format: %s", ipStr)
	}

	return ip, nil
}

// isBlocked 检查给定的 IP 是否在阻止列表中
func (m *IPBlocker) isBlocked(ip net.IP) bool {
	for _, ipNet := range m.blockedIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// refreshBlockList 刷新阻止列表
func (m *IPBlocker) refreshBlockList() error {
	// 发起 HTTP 请求获取阻止列表
	client := &http.Client{} // 使用默认的超时设置
	resp, err := client.Get(m.BlockListURL)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	var ipList []string
	if err := json.Unmarshal(body, &ipList); err != nil {
		return fmt.Errorf("json unmarshal failed: %w", err)
	}

	var validEntries int
	ipNets := make([]*net.IPNet, 0, len(ipList))

	for _, entry := range ipList {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// 尝试解析为 CIDR
		_, cidr, err := net.ParseCIDR(entry)
		if err == nil {
			ipNets = append(ipNets, cidr)
			validEntries++
			continue
		}

		// 尝试解析为普通 IP
		ip := net.ParseIP(entry)
		if ip != nil {
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			ipNets = append(ipNets, &net.IPNet{
				IP:   ip,
				Mask: mask,
			})
			validEntries++
			continue
		}

		m.logger.Warn("invalid blocklist entry", zap.String("entry", entry))
	}

	// 更新阻止列表
	m.mu.Lock()
	m.blockedIPNets = ipNets
	m.mu.Unlock()

	m.logger.Info("blocklist updated",
		zap.Int("total_entries", len(ipList)),
		zap.Int("valid_entries", validEntries),
	)

	return nil
}

// parseCaddyfile 解析 Caddyfile 配置
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m IPBlocker
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// UnmarshalCaddyfile 从 Caddyfile 中解析配置
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
			case "trust_proxy":
				m.TrustProxy = true
			case "source_headers":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.SourceHeaders = args
			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

var (
	_ caddy.Provisioner           = (*IPBlocker)(nil)
	_ caddy.Validator             = (*IPBlocker)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPBlocker)(nil)
	_ caddyfile.Unmarshaler       = (*IPBlocker)(nil)
)
