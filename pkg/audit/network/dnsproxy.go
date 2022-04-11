package network

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"text/template"

	"github.com/miekg/dns"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
)

type DNSProxy struct {
	client             *dns.Client
	dnsConfig          *dns.ClientConfig
	manager            *Manager
	originalResolvConf string
}

func dnsResponseToDNSAnswer(response *dns.Msg, fqdn string) *DNSAnswer {
	dnsAnswer := DNSAnswer{Domain: fqdn}
	for _, answer := range response.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			if record, ok := answer.(*dns.A); ok {
				dnsAnswer.Addresses = append(dnsAnswer.Addresses, record.A)
				dnsAnswer.TTL = record.Hdr.Ttl
			}
		case dns.TypeAAAA:
			if record, ok := answer.(*dns.AAAA); ok {
				dnsAnswer.Addresses = append(dnsAnswer.Addresses, record.AAAA)
				dnsAnswer.TTL = record.Hdr.Ttl
			}
		}
	}

	return &dnsAnswer
}

func (this *DNSProxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	msg.Authoritative = true
	for i, q := range r.Question {
		fqdn := msg.Question[i].Name
		res, err := this.resolve(fqdn, q.Qtype)
		if err == nil {
			msg.Answer = append(msg.Answer, res.Answer...)
		}

		if len(res.Answer) == 0 {
			continue
		}

		for _, allowedDomain := range this.manager.config.Domain.Allow {
			if toFqdn(allowedDomain) == fqdn {
				dnsAnswer := dnsResponseToDNSAnswer(res, fqdn)
				this.manager.updateAllowedFQDNist(dnsAnswer)
				break
			}
		}

		for _, deniedDomain := range this.manager.config.Domain.Deny {
			if toFqdn(deniedDomain) == fqdn {
				dnsAnswer := dnsResponseToDNSAnswer(res, fqdn)
				this.manager.updateDeniedFQDNList(dnsAnswer)
				break
			}
		}

		log.Debug(fmt.Sprintf("Domain resolved: %s (%d)", fqdn, q.Qtype))
	}

	w.WriteMsg(&msg)
}

func (this *DNSProxy) resolve(domainName string, queryType uint16) (*dns.Msg, error) {
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
	if len(dnsProxyConfig.Upstreams) != 0 {
		dnsConfig := &dns.ClientConfig{
			Servers: dnsProxyConfig.Upstreams,
		}
		return dnsConfig, nil
	}

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return dnsConfig, err
	}

	return dnsConfig, nil
}

func resolvConfFromClientConfig(dnsConfig *dns.ClientConfig) ([]byte, error) {
	resolvConfTemplate := `# This file managed by bouheki. Do not edit.

{{- range .Servers }}
nameserver {{ . }}
{{- end }}

{{- range .Search }}
search {{ . }}
{{- end }}

options edns0 trust-ad`

	tpl, err := template.New("").Parse(resolvConfTemplate)
	if err != nil {
		return nil, err
	}

	var resolvConf bytes.Buffer
	if err := tpl.Execute(&resolvConf, dnsConfig); err != nil {
		return nil, err
	}

	return resolvConf.Bytes(), nil
}

func updateResolvConf(path string, content []byte) error {
	return os.WriteFile(path, content, 0644)
}

func (mgr *Manager) StartDNSServer() error {
	resolvConfPath := "/etc/resolv.conf"

	dnsConfig, err := createDNSConfig(mgr.config.DNSProxyConfig)
	if err != nil {
		return err
	}

	srv := &dns.Server{Addr: ":" + strconv.Itoa(mgr.config.DNSProxyConfig.Port), Net: "udp"}
	srv.Handler = &DNSProxy{
		client:    new(dns.Client),
		dnsConfig: dnsConfig,
		manager:   mgr,
	}

	newDnsConfig := dns.ClientConfig{
		Servers: []string{"127.0.0.1"},
		Search:  dnsConfig.Search,
	}

	content, err := resolvConfFromClientConfig(&newDnsConfig)
	if err != nil {
		return err
	}

	if err := updateResolvConf(resolvConfPath, content); err != nil {
		return err
	}

	if err := srv.ListenAndServe(); err != nil {
		return err
	}

	return nil
}
