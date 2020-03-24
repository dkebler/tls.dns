package route53

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	tlsdns "github.com/caddyserver/tls.dns"
	"github.com/go-acme/lego/providers/dns/route53"
	"github.com/go-acme/lego/v3/challenge"
)

func init() {
	caddy.RegisterModule(Route53{})
}

// CaddyModule returns the Caddy module information.
func (Route53) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.dns.route53",
		New: func() caddy.Module { return new(Route53) },
	}
}

// Route53 configures a solver for the ACME DNS challenge.
type Route53 struct {
	tlsdns.CommonConfig
}

// NewDNSProvider returns a DNS challenge solver.
func (wrapper Route53) NewDNSProvider() (challenge.Provider, error) {
	cfg := route53.NewDefaultConfig()

	if wrapper.CommonConfig.TTL != 0 {
		cfg.TTL = wrapper.CommonConfig.TTL
	}
	if wrapper.CommonConfig.PropagationTimeout != 0 {
		cfg.PropagationTimeout = time.Duration(wrapper.CommonConfig.PropagationTimeout)
	}
	if wrapper.CommonConfig.PollingInterval != 0 {
		cfg.PollingInterval = time.Duration(wrapper.CommonConfig.PollingInterval)
	}

	return route53.NewDNSProviderConfig(cfg)
}

// Interface guard
var _ caddytls.DNSProviderMaker = (*Route53)(nil)
