package ipblocker

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
		return err
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
				m.logger.Error("failed to update IPs", zap.Error(err))
			}
		case <-m.stopChan:
			return
		}
	}
}

func (m *IPBlocker) fetchIPs() error {
	resp, err := m.httpClient.Get(m.JSONUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var ips []string
	if err := json.NewDecoder(resp.Body).Decode(&ips); err != nil {
		return err
	}

	var parsed []*net.IPNet
	for _, ipStr := range ips {
		_, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(ipStr)
			if ip == nil {
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
		zap.Int("count", len(parsed)))

	return nil
}

func (m *IPBlocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := net.ParseIP(r.RemoteAddr)
	if clientIP == nil {
		return next.ServeHTTP(w, r)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ipnet := range m.blockedIPs {
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

func (IPBlocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ip_blocker",
		New: func() caddy.Module { return new(IPBlocker) },
	}
}

var (
	_ caddy.Provisioner           = (*IPBlocker)(nil)
	_ caddy.Validator             = (*IPBlocker)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPBlocker)(nil)
)
