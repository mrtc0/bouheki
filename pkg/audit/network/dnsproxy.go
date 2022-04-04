package network

import (
	"strconv"

	"github.com/miekg/dns"
	"github.com/mrtc0/bouheki/pkg/config"
)

type handler struct {
	client    *dns.Client
	dnsConfig *dns.ClientConfig
}

func (this *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	msg.Authoritative = true
	for i, q := range r.Question {
		domain := msg.Question[i].Name
		res, err := this.resolve(domain, q.Qtype)
		if err == nil {
			msg.Answer = append(msg.Answer, res.Answer...)
		}
		// TODO: update eBPF allowed / denied Map
	}

	w.WriteMsg(&msg)
}

func (this *handler) resolve(domainName string, queryType uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(domainName, queryType)
	m.RecursionDesired = true

	res, _, err := this.client.Exchange(m, this.dnsConfig.Servers[0]+":"+this.dnsConfig.Port)
	if err != nil {
		return nil, err
	}

	return res, err
}

func createDNSConfig(dnsProxyConfig config.DNSProxyConfig) (*dns.ClientConfig, error) {
	if len(dnsProxyConfig.Upstreams) == 0 {
		dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		return dnsConfig, err
	}

	dnsConfig := &dns.ClientConfig{
		Servers: dnsProxyConfig.Upstreams,
	}

	return dnsConfig, nil
}

func StartDNSServer(dnsProxyConfig *config.DNSProxyConfig) error {
	dnsConfig, err := createDNSConfig(*dnsProxyConfig)
	if err != nil {
		return err
	}

	srv := &dns.Server{Addr: ":" + strconv.Itoa(dnsProxyConfig.Port), Net: "udp"}
	srv.Handler = &handler{
		client:    new(dns.Client),
		dnsConfig: dnsConfig,
	}

	if err := srv.ListenAndServe(); err != nil {
		return err
	}

	return nil
}
