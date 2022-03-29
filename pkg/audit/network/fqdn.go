package network

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type DNSAnswer struct {
	Domain    string
	Addresses []net.IP
	TTL       uint32
}

// To FQDN format
// e.g. example.com -> example.com.
func toFqdn(domainName string) string {
	if domainName[len(domainName)-1:] == "." {
		return domainName
	}

	return domainName + "."
}

func (r *DefaultResolver) Resolve(host string, recordType uint16) (*DNSAnswer, error) {
	r.mux.Lock()

	r.message.SetQuestion(toFqdn(host), recordType)
	r.message.RecursionDesired = true

	res, _, err := r.client.Exchange(r.message, r.config.Servers[0]+":"+r.config.Port)
	r.mux.Unlock()

	if err != nil {
		return nil, err
	}

	if res.Rcode != dns.RcodeSuccess {
		return nil, errors.New(fmt.Sprintf("Return code is %d\n", res.Rcode))
	}

	if len(res.Answer) == 0 {
		return nil, errors.New(fmt.Sprintf("%s has not records(type %d)", host, recordType))
	}

	answer := DNSAnswer{Domain: host}
	for _, rr := range res.Answer {
		switch recordType {
		case dns.TypeA:
			if record, ok := rr.(*dns.A); ok {
				answer.Addresses = append(answer.Addresses, record.A)
				answer.TTL = record.Hdr.Ttl
			}
		case dns.TypeAAAA:
			if record, ok := rr.(*dns.AAAA); ok {
				answer.Addresses = append(answer.Addresses, record.AAAA)
				answer.TTL = record.Hdr.Ttl
			}
		}
	}

	if answer.Addresses == nil {
		return nil, errors.New(fmt.Sprintf("%s has not records(type %d)", host, recordType))
	}

	return &answer, nil
}

func (mgr *Manager) ResolveAddressv4(domain string) (*DNSAnswer, error) {
	answer, err := mgr.dnsResolver.Resolve(domain, dns.TypeA)
	if err != nil {
		return nil, err
	}

	return answer, nil
}

func (mgr *Manager) ResolveAddressv6(domain string) (*DNSAnswer, error) {
	answer, err := mgr.dnsResolver.Resolve(domain, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}

	return answer, nil
}
