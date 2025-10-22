package main

import (
	"fmt"
	"log"
	"net"

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

	// 7. Format Output (Multi-TXT Segmentation)
	segments := formatter.FormatSegments(finalIPNets, cfg.TargetDomain)

	// --- Output Results ---

	log.Println("\n=======================================================")
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
		fullRecordName := fmt.Sprintf("%s.%s", recordName, cfg.TargetDomain)

		fmt.Printf("%s IN TXT \"%s\"\n", fullRecordName, segment)

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
