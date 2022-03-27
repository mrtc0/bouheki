package network

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type DNSAnswerCache struct {
	Domain    string
	Addresses []net.IP
	TTL       uint32
}

// Domain Name to FQDN
// e.g. example.com -> example.com.
func domainNameToFqdn(domainName string) string {
	if domainName[len(domainName)-1:] == "." {
		return domainName
	}

	return domainName + "."
}

func (r *DefaultResolver) Resolve(host string, recordType uint16) (DNSAnswerCache, error) {
	answers := DNSAnswerCache{Domain: host}

	r.message.SetQuestion(domainNameToFqdn(host), recordType)
	r.message.RecursionDesired = true

	res, _, err := r.client.Exchange(r.message, r.config.Servers[0]+":"+r.config.Port)
	if err != nil {
		return answers, err
	}

	if res.Rcode != dns.RcodeSuccess {
		return answers, errors.New(fmt.Sprintf("Return code is %d\n", res.Rcode))
	}

	var addresses []net.IP
	for _, answer := range res.Answer {
		switch recordType {
		case dns.TypeA:
			if a, ok := answer.(*dns.A); ok {
				addresses = append(addresses, a.A)
				answers.TTL = a.Hdr.Ttl
			}
		case dns.TypeAAAA:
			if aaaa, ok := answer.(*dns.AAAA); ok {
				addresses = append(addresses, aaaa.AAAA)
				answers.TTL = aaaa.Hdr.Ttl
			}
		}
	}
	answers.Addresses = addresses

	return answers, nil
}

func (mgr *Manager) updateAllowedDomainList(domain string, queryType uint16) (DNSAnswerCache, error) {
	answer, err := mgr.dnsResolver.Resolve(domain, queryType)
	if err != nil || len(answer.Addresses) == 0 {
		return answer, err
	}
	fmt.Printf("A %s is %s, TTL is %d\n", domain, answer.Addresses, answer.TTL)
	mgr.setAllowedDomainList(domain, answer.Addresses)

	return answer, nil
}

func (mgr *Manager) updateDeniedDomainList(domain string, queryType uint16) (DNSAnswerCache, error) {
	answer, err := mgr.dnsResolver.Resolve(domain, queryType)
	if err != nil || len(answer.Addresses) == 0 {
		return answer, err
	}
	fmt.Printf("A %s is %s, TTL is %d\n", domain, answer.Addresses, answer.TTL)
	mgr.setDeniedDomainList(domain, answer.Addresses)

	return answer, nil
}
