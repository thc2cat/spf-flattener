// Fichier: dns/resolver.go (Logique du Cœur du Flattening)

package dns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"project/spf-flattener/cidr"

	"github.com/miekg/dns"
)

const maxDNSLookups = 10 // Standard SPF lookup limit
const dnsTimeout = 5 * time.Second

// FlattenedResult contains the result of the SPF flattening process.
type FlattenedResult struct {
	IPNets        cidr.NetAddrSlice
	TotalLookups  int
	InitialDomain string
	SLD           string // Second Level Domain
}

// Resolver manages DNS lookups with concurrency and state.
type Resolver struct {
	client *dns.Client
	// lookupTracker maps FQDNs that initiated a DNS lookup to prevent cycles and count lookups.
	lookupTracker map[string]struct{}
	// Mutex to protect concurrent access to lookupTracker.
	mu sync.Mutex
	// Semaphore to limit concurrent goroutines for DNS lookups.
	semaphore chan struct{}
}

// NewResolver creates a new Resolver instance.
func NewResolver(concurrencyLimit int) *Resolver {
	return &Resolver{
		client:        &dns.Client{Timeout: dnsTimeout},
		lookupTracker: make(map[string]struct{}),
		semaphore:     make(chan struct{}, concurrencyLimit),
	}
}

// GetLookupCount safely returns the current number of unique lookups tracked.
func (r *Resolver) GetLookupCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lookupTracker)
}

// resolveDNS performs the actual MIEKG DNS query and handles SERVFAIL/Timeout (Fail-Fast).
func (r *Resolver) resolveDNS(domain string, qtype uint16) (*dns.Msg, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	// Use a standard public resolver for simplicity (e.g., Google DNS)
	// In a production environment, one might use /etc/resolv.conf settings.
	resp, _, err := c.Exchange(m, "193.51.24.1:53")

	if err != nil {
		return nil, fmt.Errorf("DNS query error for %s (%s): %w", domain, dns.TypeToString[qtype], err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response failed for %s (%s). Rcode: %s", domain, dns.TypeToString[qtype], dns.RcodeToString[resp.Rcode])
	}

	return resp, nil
}

// ResolveAAndAAAA performs a simple A and AAAA lookup and returns the results as NetAddr.
func (r *Resolver) ResolveAAndAAAA(domain string, isPriority bool, priorityIndex int) (cidr.NetAddrSlice, error) {
	var results cidr.NetAddrSlice

	// A and AAAA lookups do not count towards the SPF 10 lookup limit.

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := r.resolveDNS(domain, qtype)
		if err != nil {
			// Log and continue if simple A/AAAA fails, unless it's a priority fail-fast point.
			log.Printf("Warning: Failed to resolve %s records for %s: %v", dns.TypeToString[qtype], domain, err)
			if isPriority {
				return nil, err // Fail-fast for critical priority entries
			}
			continue
		}

		for _, ans := range resp.Answer {
			switch t := ans.(type) {
			case *dns.A:
				// Use /32 for A records
				mask := net.CIDRMask(32, 32)
				results = append(results, &cidr.NetAddr{
					IPNet:                 &net.IPNet{IP: t.A, Mask: mask},
					IsPriority:            isPriority,
					OriginalPriorityIndex: priorityIndex,
				})
			case *dns.AAAA:
				// Use /128 for AAAA records
				mask := net.CIDRMask(128, 128)
				results = append(results, &cidr.NetAddr{
					IPNet:                 &net.IPNet{IP: t.AAAA, Mask: mask},
					IsPriority:            isPriority,
					OriginalPriorityIndex: priorityIndex,
				})
			}
		}
	}
	return results, nil
}

// FlattenSPF recursively resolves the SPF record for a given domain, handling concurrency and limits.
func (r *Resolver) FlattenSPF(domain string, initialDomain string, isPriority bool, priorityIndex int) (cidr.NetAddrSlice, error) {
	// Fail-Fast: Check lookup limit
	if r.GetLookupCount() >= maxDNSLookups {
		return nil, fmt.Errorf("lookup limit of %d reached for domain %s (current count: %d)",
			maxDNSLookups, domain, r.GetLookupCount())
	}

	r.mu.Lock()
	// Fail-Fast: Check for recursion/cycle
	if _, ok := r.lookupTracker[domain]; ok {
		r.mu.Unlock()
		log.Printf("Warning: Detected recursion/cycle for domain %s, skipping.", domain)
		return nil, nil
	}

	// Track the lookup
	r.lookupTracker[domain] = struct{}{}
	r.mu.Unlock()

	log.Printf("INFO: Starting SPF resolution for %s (Lookup #%d)", domain, r.GetLookupCount())

	// Resolve TXT record
	resp, err := r.resolveDNS(domain, dns.TypeTXT)
	if err != nil {
		log.Printf("ERROR: Fail-fast: DNS TXT resolution failed for domain %s: %v", domain, err)
		return nil, err
	}

	// Find SPF record
	spfRecord := ""
	for _, ans := range resp.Answer {
		if t, ok := ans.(*dns.TXT); ok && len(t.Txt) > 0 && strings.HasPrefix(strings.ToLower(t.Txt[0]), "v=spf1") {
			spfRecord = strings.Join(t.Txt, "")
			break
		}
	}

	if spfRecord == "" {
		log.Printf("Warning: No valid SPF record found for %s. Skipping.", domain)
		return nil, nil
	}

	// Process mechanisms sequentially
	mechanisms := strings.Fields(spfRecord)[1:] // Skip "v=spf1"
	var allNets cidr.NetAddrSlice

	for _, mechanism := range mechanisms {
		if strings.HasPrefix(mechanism, "a") ||
			strings.HasPrefix(mechanism, "mx") ||
			strings.HasPrefix(mechanism, "ptr") ||
			strings.HasPrefix(mechanism, "ip4") ||
			strings.HasPrefix(mechanism, "ip6") ||
			strings.HasPrefix(mechanism, "include") {

			nets, err := r.resolveMechanism(domain, mechanism, isPriority, priorityIndex, initialDomain)
			if err != nil {
				return nil, fmt.Errorf("error resolving mechanism %s in %s: %w", mechanism, domain, err)
			}
			allNets = append(allNets, nets...)
		}
	}

	return allNets, nil
}

// resolveMechanism handles the logic for different SPF mechanisms.
func (r *Resolver) resolveMechanism(baseDomain, mechanism string, isPriority bool, priorityIndex int, initialDomain string) (cidr.NetAddrSlice, error) {
	// IP4/IP6: Direct CIDR inclusion (no DNS lookup)
	if strings.HasPrefix(mechanism, "ip4:") || strings.HasPrefix(mechanism, "ip6:") {
		cidrText := mechanism[4:]

		// Try plain IP first (no mask)
		if ip := net.ParseIP(cidrText); ip != nil {
			// Validate family matches mechanism
			if strings.HasPrefix(mechanism, "ip4:") {
				if ip = ip.To4(); ip == nil {
					return nil, fmt.Errorf("expected IPv4 address for %s", mechanism)
				}
				mask := net.CIDRMask(32, 32)
				return cidr.NetAddrSlice{
					&cidr.NetAddr{IPNet: &net.IPNet{IP: ip, Mask: mask}, IsPriority: isPriority, OriginalPriorityIndex: priorityIndex},
				}, nil
			}
			// ip6:
			if ip = ip.To16(); ip == nil {
				return nil, fmt.Errorf("expected IPv6 address for %s", mechanism)
			}
			mask := net.CIDRMask(128, 128)
			return cidr.NetAddrSlice{
				&cidr.NetAddr{IPNet: &net.IPNet{IP: ip, Mask: mask}, IsPriority: isPriority, OriginalPriorityIndex: priorityIndex},
			}, nil
		}

		// Fallback: try CIDR parsing (address/prefix)
		_, ipNet, err := net.ParseCIDR(cidrText)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR syntax in SPF record: %s", mechanism)
		}
		return cidr.NetAddrSlice{
			&cidr.NetAddr{IPNet: ipNet, IsPriority: isPriority, OriginalPriorityIndex: priorityIndex},
		}, nil
	}

	// INCLUDE: Recursive call (uses 1 DNS lookup)
	if strings.HasPrefix(mechanism, "include:") {
		includedDomain := mechanism[8:]
		if includedDomain == baseDomain {
			log.Printf("Warning: Skipping self-referential include: %s", includedDomain)
			return nil, nil
		}
		// Recursive call: The result will be added to the final list
		return r.FlattenSPF(includedDomain, initialDomain, isPriority, priorityIndex)
	}

	// A, MX, PTR: Need DNS resolution
	targetDomain := baseDomain // Default to baseDomain for a, mx, ptr without parameters
	if strings.Contains(mechanism, ":") {
		// Example: a:other.com, mx:mail.other.com
		parts := strings.SplitN(mechanism, ":", 2)
		targetDomain = parts[1]
	}

	switch {
	case strings.HasPrefix(mechanism, "a"):
		// A mechanism: Resolve A/AAAA records for the target domain
		return r.ResolveAAndAAAA(targetDomain, isPriority, priorityIndex)

	case strings.HasPrefix(mechanism, "mx"):
		// MX mechanism: Resolve MX records, then A/AAAA for each MX host
		return r.resolveMX(targetDomain, isPriority, priorityIndex)

	case strings.HasPrefix(mechanism, "ptr"):
		// PTR mechanism: PTR is generally discouraged. Resolve it if required.
		// (Implementation of PTR resolution is complex and often skipped in real flatteners,
		// but we respect the requirement)
		log.Printf("Warning: PTR mechanism found for %s. PTR records are highly discouraged and may be skipped by some receivers.", targetDomain)
		return r.resolvePTR(targetDomain, isPriority, priorityIndex)

	default:
		// Unknown mechanism (like exists, redirect, or simple 'a' without domain)
		return nil, nil
	}
}

// resolveMX performs resolution for the 'mx' mechanism.
func (r *Resolver) resolveMX(domain string, isPriority bool, priorityIndex int) (cidr.NetAddrSlice, error) {
	resp, err := r.resolveDNS(domain, dns.TypeMX)
	if err != nil {
		log.Printf("ERROR: Failed to resolve MX records for %s: %v", domain, err)
		return nil, err
	}

	var allNets cidr.NetAddrSlice

	for _, ans := range resp.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			// Resolve A/AAAA records for each MX host sequentially
			nets, err := r.ResolveAAndAAAA(mx.Mx, isPriority, priorityIndex)
			if err != nil {
				log.Printf("Warning: Failed to resolve A/AAAA for MX host %s: %v", mx.Mx, err)
				continue // Skip this MX host on error but continue with others
			}
			allNets = append(allNets, nets...)
		}
	}

	return allNets, nil
}

// resolvePTR performs resolution for the 'ptr' mechanism (simplistic implementation).
func (r *Resolver) resolvePTR(domain string, isPriority bool, priorityIndex int) (cidr.NetAddrSlice, error) {
	// A PTR mechanism requires checking if the connecting IP resolves to the domain,
	// and then if one of the resolved A/AAAA records for that domain matches the connecting IP.
	// Since we are *flattening* and not *validating* a connection, we must simulate the necessary output.

	// A common, albeit imperfect, flattening strategy for PTR is to list all IPs associated
	// with the domain's A/AAAA records, as if they *could* pass the PTR check.
	// We'll stick to resolving A/AAAA of the target domain for simplicity in flattening.

	return r.ResolveAAndAAAA(domain, isPriority, priorityIndex)
}
