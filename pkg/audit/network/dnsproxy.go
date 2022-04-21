package network

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
)

const (
	dockerDNSBindAddress = "172.17.0.1"
	hostDNSBindAddress   = "127.0.0.1"
)

type DNSProxy struct {
	client    *dns.Client
	dnsConfig *dns.ClientConfig
	manager   *Manager
}

func dnsResponseToDNSAnswer(response *dns.Msg) *DNSAnswer {
	dnsAnswer := DNSAnswer{}
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

func updateDNSCache(fqdn string, dnsAnswer *DNSAnswer) {
	for _, address := range dnsAnswer.Addresses {
		dnsCache[address.String()] = fqdn
	}
}

func (this *DNSProxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	msg.Authoritative = true
	for i, q := range r.Question {
		fqdn := msg.Question[i].Name
		res, err := this.resolve(fqdn, q.Qtype)
		if err != nil {
			log.Error(err)
			continue
		}

		msg.Answer = append(msg.Answer, res.Answer...)
		dnsAnswer := dnsResponseToDNSAnswer(res)
		dnsAnswer.Domain = fqdn

		updateDNSCache(fqdn, dnsAnswer)

		for _, allowedDomain := range this.manager.config.Domain.Allow {
			if toFqdn(allowedDomain) == fqdn {
				this.manager.updateAllowedFQDNist(dnsAnswer)
				break
			}
		}

		for _, deniedDomain := range this.manager.config.Domain.Deny {
			if toFqdn(deniedDomain) == fqdn {
				this.manager.updateDeniedFQDNList(dnsAnswer)
				break
			}
		}

		log.Debug(fmt.Sprintf("Domain resolved: %s (%d)\n", fqdn, q.Qtype))
		log.Debug(fmt.Sprintf("Current DNS Cache: %#v\n", dnsCache))
	}

	w.WriteMsg(&msg)
}

func (this *DNSProxy) resolve(domainName string, queryType uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(domainName, queryType)
	m.RecursionDesired = true

	res, _, err := this.client.Exchange(m, this.dnsConfig.Servers[0]+":"+"53")
	if err != nil {
		return nil, err
	}

	return res, err
}

func createDNSConfig(dnsProxyConfig config.DNSProxyConfig) (*dns.ClientConfig, error) {
	dnsConfig := &dns.ClientConfig{
		Servers: dnsProxyConfig.Upstreams,
	}

	return dnsConfig, nil
}

func (mgr *Manager) StartDNSServer(bindAddress string) error {
	dnsConfig, err := createDNSConfig(mgr.config.DNSProxyConfig)
	if err != nil {
		return err
	}

	srv := &dns.Server{Addr: bindAddress + ":53", Net: "udp"}
	srv.Handler = &DNSProxy{
		client:    new(dns.Client),
		dnsConfig: dnsConfig,
		manager:   mgr,
	}

	if err := srv.ListenAndServe(); err != nil {
		return err
	}

	return nil
}
