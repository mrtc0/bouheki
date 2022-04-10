package network

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"text/template"

	"github.com/miekg/dns"
	"github.com/mrtc0/bouheki/pkg/config"
)

type handler struct {
	client    *dns.Client
	dnsConfig *dns.ClientConfig
	manager   *Manager
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

		// TODO: Refactor
		// resolv.conf から読み込んだあと、resolve.conf を動的に書き換えないといけない
		for _, allowedFqdn := range this.manager.config.Domain.Allow {
			dnsAnswer := DNSAnswer{Domain: domain}
			if allowedFqdn == domain {
				for _, answer := range res.Answer {
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
				fmt.Printf("update allowed map: %#v\n", dnsAnswer)
				this.manager.updateAllowedFQDNist(&dnsAnswer)
			}
		}

		for _, deniedFqdn := range this.manager.config.Domain.Deny {
			dnsAnswer := DNSAnswer{Domain: domain}
			if deniedFqdn+"." == domain {
				fmt.Printf("%#v\n", res)
				for _, answer := range res.Answer {
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
				fmt.Printf("update deny map: %#v\n", dnsAnswer)
				this.manager.updateDeniedFQDNList(&dnsAnswer)
			}
		}
		fmt.Printf("resolved %s\n", domain)
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

	if usingSystemdResolved(dnsConfig) {
		dnsConfig, err := dns.ClientConfigFromFile("/run/systemd/resolve/resolv.conf")
		if err != nil {
			return dnsConfig, err
		}
	}

	return dnsConfig, nil
}

func usingSystemdResolved(dnsConfig *dns.ClientConfig) bool {
	for _, server := range dnsConfig.Servers {
		if server == "127.0.0.53" {
			return true
		}
	}

	return false
}

func resolvConfFromClientConfig(dnsConfig *dns.ClientConfig) ([]byte, error) {
	resolvConfTemplate := `# This file managed by bouheki. Do not edit.

{{- range .Servers }}
nameserver {{ . }}
{{- end }}

{{- range .Search }}
search {{ . }}
{{- end }}

options edns0 trust-ad
	`

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
	srv.Handler = &handler{
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
