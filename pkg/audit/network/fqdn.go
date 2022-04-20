package network

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	log "github.com/mrtc0/bouheki/pkg/log"
)

type DNSAnswer struct {
	Domain    string
	Addresses []net.IP
	TTL       uint32
}

var dnsCache map[string]string

func initDNSCache() {
	if dnsCache == nil {
		dnsCache = make(map[string]string)
	}
}

// To FQDN format
// e.g. example.com -> example.com.
func toFqdn(domainName string) string {
	if domainName[len(domainName)-1:] == "." {
		return domainName
	}

	return domainName + "."
}

func (r *DefaultResolver) exchange(message *dns.Msg) (*dns.Msg, error) {
	for _, server := range r.config.Servers {
		res, _, err := r.client.Exchange(r.message, server+":53")
		if err != nil {
			log.Error(err)
			continue
		}
		return res, err
	}

	return nil, errors.New("resolve failed")
}

func (r *DefaultResolver) Resolve(host string, recordType uint16) (*DNSAnswer, error) {
	r.mux.Lock()

	r.message.SetQuestion(toFqdn(host), recordType)
	r.message.RecursionDesired = true

	res, err := r.exchange(r.message)
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

func (mgr *Manager) resolveAndUpdateAllowedFQDNList(domainName string, recordType uint16) (uint32, error) {
	switch recordType {
	case dns.TypeA:
		answer, err := mgr.ResolveAddressv4(domainName)
		if err != nil {
			log.Debug(fmt.Sprintf("%s (A) resolve failed. %s\n", domainName, err))
			return 5, nil
		}
		err = mgr.updateAllowedFQDNist(answer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("%s (A) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	case dns.TypeAAAA:
		answer, err := mgr.ResolveAddressv6(domainName)
		if err != nil {
			log.Debug(fmt.Sprintf("%s (AAAA) resolve failed. %s\n", domainName, err))
			return 5, nil
		}
		err = mgr.updateAllowedFQDNist(answer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("%s (AAAA) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	}

	return 5, errors.New("invalid record type")
}

func (mgr *Manager) resolveAndUpdateDeniedFQDNList(domainName string, recordType uint16) (uint32, error) {
	switch recordType {
	case dns.TypeA:
		answer, err := mgr.ResolveAddressv4(domainName)
		if err != nil {
			log.Debug(fmt.Sprintf("%s (A) resolve failed. %s\n", domainName, err))
			return 5, nil
		}
		err = mgr.updateDeniedFQDNList(answer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("%s (A) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	case dns.TypeAAAA:
		answer, err := mgr.ResolveAddressv6(domainName)
		if err != nil {
			log.Debug(fmt.Sprintf("%s (AAAA) resolve failed. %s\n", domainName, err))
			return 5, nil
		}
		err = mgr.updateDeniedFQDNList(answer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("%s (AAAA) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	}

	return 5, errors.New("invalid record type")
}

func (mgr *Manager) AsyncResolve() {
	for _, allowedDomain := range mgr.config.RestrictedNetworkConfig.Domain.Allow {
		go func(domainName string) {
			for {
				ttl, err := mgr.resolveAndUpdateAllowedFQDNList(domainName, dns.TypeA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(allowedDomain)

		go func(domainName string) {
			for {
				ttl, err := mgr.resolveAndUpdateAllowedFQDNList(domainName, dns.TypeAAAA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(allowedDomain)
	}

	for _, deniedDomain := range mgr.config.RestrictedNetworkConfig.Domain.Deny {
		go func(domainName string) {
			for {
				ttl, err := mgr.resolveAndUpdateDeniedFQDNList(domainName, dns.TypeA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(deniedDomain)

		go func(domainName string) {
			for {
				ttl, err := mgr.resolveAndUpdateDeniedFQDNList(domainName, dns.TypeAAAA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(deniedDomain)
	}
}
