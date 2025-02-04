package ipblocker

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(IPBlocker{})
}

type IPBlocker struct {
	JSONUrl  string        `json:"json_url,omitempty"`
	Interval time.Duration `json:"interval,omitempty"`

	logger     *zap.Logger
	httpClient *http.Client
	blockedIPs []*net.IPNet
	mu         sync.RWMutex
	stopChan   chan struct{}
}

func (m *IPBlocker) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.httpClient = &http.Client{Timeout: 10 * time.Second}
	m.stopChan = make(chan struct{})

	// Initial fetch
	if err := m.fetchIPs(); err != nil {
		return fmt.Errorf("initial IP fetch failed: %w", err)
	}

	// Start updater
	if m.Interval > 0 {
		go m.updater()
	}

	return nil
}

func (m *IPBlocker) Validate() error {
	if m.JSONUrl == "" {
		return fmt.Errorf("json_url is required")
	}
	return nil
}

func (m *IPBlocker) updater() {
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.fetchIPs(); err != nil {
				m.logger.Error("failed to update IPs", zap.Error(err), zap.String("json_url", m.JSONUrl))
			}
		case <-m.stopChan:
			return
		}
	}
}

func (m *IPBlocker) fetchIPs() error {
	resp, err := m.httpClient.Get(m.JSONUrl)
	if err != nil {
		return fmt.Errorf("failed to fetch IPs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	var ips []string
	if err := json.NewDecoder(resp.Body).Decode(&ips); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}

	var parsed []*net.IPNet
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		_, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(ipStr)
			if ip == nil {
				m.logger.Warn("invalid IP format", zap.String("ip", ipStr))
				continue
			}
			ipnet = &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(32, 32),
			}
			if ip.To4() == nil {
				ipnet.Mask = net.CIDRMask(128, 128)
			}
		}
		parsed = append(parsed, ipnet)
	}

	m.mu.Lock()
	m.blockedIPs = parsed
	m.mu.Unlock()

	m.logger.Info("updated blocked IP list",
		zap.Int("count", len(parsed)),
		zap.String("json_url", m.JSONUrl),
		zap.Time("updated_at", time.Now()))

	return nil
}

func (m *IPBlocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.logger.Warn("failed to parse RemoteAddr", zap.String("remote_addr", r.RemoteAddr))
		return next.ServeHTTP(w, r)
	}

	clientIP := net.ParseIP(host)
	if clientIP == nil {
		m.logger.Warn("failed to parse client IP", zap.String("remote_addr", r.RemoteAddr))
		return next.ServeHTTP(w, r)
	}

	// Copy the blocked IP list to reduce lock contention
	m.mu.RLock()
	blockedIPs := m.blockedIPs
	m.mu.RUnlock()

	for _, ipnet := range blockedIPs {
		if ipnet.Contains(clientIP) {
			m.logger.Debug("blocked request",
				zap.String("ip", clientIP.String()),
				zap.String("path", r.URL.Path))

			w.WriteHeader(http.StatusForbidden)
			return nil
		}
	}

	return next.ServeHTTP(w, r)
}

func (m *IPBlocker) Cleanup() error {
	close(m.stopChan)
	return nil
}

func (IPBlocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ip_blocker",
		New: func() caddy.Module { return new(IPBlocker) },
	}
}

var (
	_ caddy.Provisioner           = (*IPBlocker)(nil)
	_ caddy.CleanerUpper          = (*IPBlocker)(nil)
	_ caddy.Validator             = (*IPBlocker)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPBlocker)(nil)
)
