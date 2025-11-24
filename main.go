package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"project/spf-flattener/cidr"
	"project/spf-flattener/config"
	"project/spf-flattener/dns"
	"project/spf-flattener/formatter"
)

const configFile = "spf-flattener-config.yaml"

func main() {
	// 1. Load Configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("ERROR: Failed to load configuration from %s: %v", configFile, err)
	}
	log.Printf("INFO: Configuration loaded successfully. Concurrency limit: %d", cfg.ConcurrencyLimit)

	// Vérifier que targetDomain est défini
	if cfg.TargetDomain == "" {
		log.Fatalf("ERROR: targetDomain not defined in configuration file")
	}

	// Utiliser le targetDomain de la configuration
	targetDomain := "spf-unflat." + cfg.TargetDomain

	// --- Core Processing ---

	// 3. Initialize Resolver with Concurrency Control
	resolver := dns.NewResolver(cfg.ConcurrencyLimit)

	// 4. Resolve Priority Entries (synchronously to preserve configuration order)
	var priorityIPNets cidr.NetAddrSlice

	for i, entry := range cfg.PriorityEntries {
		resolved, err := resolvePriorityEntry(resolver, entry, i)
		if err != nil {
			// Fail-fast on priority resolution failure
			log.Fatalf("FAIL-FAST: Failed to resolve priority entry '%s': %v", entry, err)
		}
		priorityIPNets = append(priorityIPNets, resolved...)
	}
	log.Printf("INFO: Found %d unique network addresses from priority entries.", len(priorityIPNets))

	// 5. Recursive SPF Flattening for Target Domain
	// Note: The FlattenSPF implementation will handle recursion and lookups count.
	nonPriorityIPNets, err := resolver.FlattenSPF(targetDomain, targetDomain, false, -1)
	if err != nil {
		// Fail-fast on main SPF resolution failure
		log.Fatalf("FAIL-FAST: Failed to flatten SPF for %s: %v", targetDomain, err)
	}
	log.Printf("INFO: Found %d network addresses from the main SPF chain.", len(nonPriorityIPNets))

	// 6. Combine, Deduplicate, and Sort All Addresses
	allIPNets := append(priorityIPNets, nonPriorityIPNets...)
	finalIPNets := cidr.DeduplicateAndSort(allIPNets)

	// Check current TXT spf record and compare with finalIPNets
	entryName := "_spf." + cfg.TargetDomain
	currentCIDRs, err := fetchSPFAndResolveIncludes(entryName, cfg.MaxLookups)
	if err != nil {
		log.Printf("WARN: Failed to fetch current SPF (and includes) at %s: %v", entryName, err)
	} else {
		compareAndReportCIDRs(finalIPNets, currentCIDRs, entryName)
	}

	// 7. Format Output (Multi-TXT Segmentation)
	segments := formatter.FormatSegments(finalIPNets, cfg.TargetDomain)

	// --- Output Results ---

	log.Println("=======================================================")
	log.Println("             SPF FLATTENING RESULTS")
	log.Println("=======================================================")
	log.Printf("Initial Domain: %s\n", targetDomain)
	log.Printf("Total DNS Lookups Used (Recursive Includes): %d / %d\n",
		resolver.GetLookupCount(), cfg.MaxLookups)
	log.Printf("Total Unique CIDRs Generated: %d\n", len(finalIPNets))
	log.Println("-------------------------------------------------------")

	// Print the generated TXT records
	for i, segment := range segments {
		recordName := "_spf"
		if i > 0 {
			recordName = fmt.Sprintf("spf%d", i) // spf1, spf2, ... (since the first segment is index 0)
		}

		// The entry point record is _spf.domain.com
		fullRecordName := fmt.Sprintf("%s", recordName)

		fmt.Printf("%s 600 IN TXT \"%s\"\n", fullRecordName, segment)

	}

}

// resolvePriorityEntry resolves a single priority entry (CIDR or domain) into NetAddr slice.
func resolvePriorityEntry(r *dns.Resolver, entry string, index int) (cidr.NetAddrSlice, error) {
	// Check if it's already a CIDR
	if _, ipNet, err := net.ParseCIDR(entry); err == nil {
		return cidr.NetAddrSlice{&cidr.NetAddr{
			IPNet:                 ipNet,
			IsPriority:            true,
			OriginalPriorityIndex: index,
		}}, nil
	}

	// Assume it's a domain and perform DNS resolution (A/AAAA)
	// NOTE: MX/PTR mechanisms are typically not processed for simple priority domains,
	// only for domains found in the SPF chain. If the requirement was to process MX/PTR
	// here too, we would call a specific resolver function.

	// A simple A/AAAA lookup for a priority domain
	return r.ResolveAAndAAAA(entry, true, index)
}

// fetchSPFAndResolveIncludes looks up the given name and recursively follows include: mechanisms,
// collecting all ip4/ip6 CIDRs found. It uses a simple BFS with a visited set and limits the number
// of lookups by maxLookups to avoid loops.
func fetchSPFAndResolveIncludes(name string, maxLookups int) ([]string, error) {
	var cidrs []string
	visited := make(map[string]struct{})
	queue := []string{name}
	lookups := 0

	for len(queue) > 0 {
		if lookups >= maxLookups {
			return cidrs, fmt.Errorf("max lookups (%d) reached while resolving SPF includes", maxLookups)
		}
		d := queue[0]
		queue = queue[1:]

		// avoid duplicate lookups
		if _, ok := visited[d]; ok {
			continue
		}
		visited[d] = struct{}{}
		lookups++

		txts, err := net.LookupTXT(d)
		if err != nil {
			// continue processing other includes; report at end if nothing found
			log.Printf("WARN: LookupTXT failed for %s: %v", d, err)
			continue
		}

		foundSPF := false
		for _, txt := range txts {
			t := strings.TrimSpace(txt)
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				foundSPF = true
				c, includes := parseSPFToCIDRsAndIncludes(t)
				cidrs = append(cidrs, c...)
				// enqueue includes
				for _, inc := range includes {
					// Per RFC include target is a domain; enqueue as-is
					if _, seen := visited[inc]; !seen {
						queue = append(queue, inc)
					}
				}
				// do not break: in case multiple TXT records contain fragments, parse them all
			}
		}
		if !foundSPF {
			// No SPF at this name; continue
			continue
		}
	}

	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no v=spf1 TXT records (or cidrs) found under %s and its includes", name)
	}

	// Normalize and dedupe CIDRs
	normalized := make(map[string]struct{})
	var out []string
	for _, s := range cidrs {
		normalized[s] = struct{}{}
	}
	for k := range normalized {
		out = append(out, k)
	}
	return out, nil
}

// parseSPFToCIDRsAndIncludes extracts ip4/ip6 CIDRs and include: targets from a single spf string.
// It normalizes bare IPs to CIDRs (/32 or /128).
func parseSPFToCIDRsAndIncludes(spf string) (cidrs []string, includes []string) {
	toks := strings.Fields(spf)
	if len(toks) == 0 {
		return
	}
	for _, tok := range toks[1:] { // skip "v=spf1"
		if tok == "" {
			continue
		}
		// strip leading qualifier + - ~ ?
		if strings.ContainsAny(tok[:1], "+-~?") && len(tok) > 1 {
			tok = tok[1:]
		}

		if strings.HasPrefix(tok, "include:") {
			inc := strings.TrimPrefix(tok, "include:")
			// include may have a trailing qualifier (unlikely) but trim spaces
			inc = strings.TrimSpace(inc)
			if inc != "" {
				includes = append(includes, inc)
			}
			continue
		}

		if strings.HasPrefix(tok, "ip4:") || strings.HasPrefix(tok, "ip6:") {
			addr := tok[4:]
			// try CIDR
			if _, ipnet, err := net.ParseCIDR(addr); err == nil {
				cidrs = append(cidrs, ipnet.String())
				continue
			}
			// try plain IP
			if ip := net.ParseIP(addr); ip != nil {
				if strings.HasPrefix(tok, "ip4:") {
					mask := net.CIDRMask(32, 32)
					ipnet := &net.IPNet{IP: ip, Mask: mask}
					cidrs = append(cidrs, ipnet.String())
				} else {
					mask := net.CIDRMask(128, 128)
					ipnet := &net.IPNet{IP: ip, Mask: mask}
					cidrs = append(cidrs, ipnet.String())
				}
			}
		}
	}
	return
}

// compareAndReportCIDRs compares the generated list (final) with the current published CIDRs and logs differences.
func compareAndReportCIDRs(final cidr.NetAddrSlice, current []string, recordName string) {
	finalSet := make(map[string]struct{}, len(final))
	for _, n := range final {
		finalSet[n.IPNet.String()] = struct{}{}
	}

	currentSet := make(map[string]struct{}, len(current))
	for _, c := range current {
		currentSet[c] = struct{}{}
	}

	var missing []string // in final but not in current (should be added)
	for f := range finalSet {
		if _, ok := currentSet[f]; !ok {
			missing = append(missing, f)
		}
	}

	var extra []string // in current but not in final (should be removed)
	for c := range currentSet {
		if _, ok := finalSet[c]; !ok {
			extra = append(extra, c)
		}
	}

	if len(missing) == 0 && len(extra) == 0 {
		log.Printf("OK: Published SPF at %s matches generated CIDRs (%d entries).", recordName, len(final))
		return
	}

	log.Printf("DIFFERENCE: Published SPF at %s does not match generated CIDRs.", recordName)
	if len(missing) > 0 {
		log.Printf("  Missing in DNS (present in generated final list):")
		for _, m := range missing {
			log.Printf("    + %s", m)
		}
	}
	if len(extra) > 0 {
		log.Printf("  Extra in DNS (not present in generated final list):")
		for _, e := range extra {
			log.Printf("    - %s", e)
		}
	}
}
