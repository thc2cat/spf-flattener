// Fichier: cidr/sort.go

package cidr

import (
	"net"
	"sort"
)

// DeduplicateAndSort removes duplicates and applies the custom sorting logic.
func DeduplicateAndSort(addrs NetAddrSlice) NetAddrSlice {
	// 1. Déduplication (using a map to track unique CIDR strings)
	uniqueCIDRs := make(map[string]*NetAddr)
	for _, addr := range addrs {
		cidrStr := addr.IPNet.String()
		if _, found := uniqueCIDRs[cidrStr]; !found || addr.IsPriority {
			// If not found, add it. If found, only replace if the new one is priority,
			// or if the existing one is not priority (to keep the priority flag).
			uniqueCIDRs[cidrStr] = addr
		}
	}

	var result NetAddrSlice
	for _, addr := range uniqueCIDRs {
		result = append(result, addr)
	}

	// 2. Tri Personnalisé
	sort.Slice(result, func(i, j int) bool {
		a := result[i]
		b := result[j]

		// Règle 1: Les prioritaires passent avant les non-prioritaires.
		if a.IsPriority != b.IsPriority {
			return a.IsPriority
		}

		// Règle 2: Tri entre deux prioritaires (par ordre de configuration).
		if a.IsPriority && b.IsPriority {
			return a.OriginalPriorityIndex < b.OriginalPriorityIndex
		}

		// Règle 3: Tri entre deux non-prioritaires (tri numérique : IPv4 avant IPv6, puis valeur).
		// (This logic needs robust implementation of IP comparison)
		return compareIPNets(a.IPNet, b.IPNet)
	})

	return result
}

// Helper function to implement the numerical sorting of IPNets.
func compareIPNets(a, b *net.IPNet) bool {
	// 1. IPv4 before IPv6
	isA4 := a.IP.To4() != nil
	isB4 := b.IP.To4() != nil
	if isA4 != isB4 {
		return isA4 // True if A is IPv4 and B is IPv6
	}

	// 2. Compare IPs numerically
	return compareIP(a.IP, b.IP)
}

// Simple numerical IP comparison.
func compareIP(a, b net.IP) bool {
	// Ensure comparison is done on 16-byte representation (IPv6 or mapped IPv4)
	a16 := a.To16()
	b16 := b.To16()

	for i := 0; i < len(a16); i++ {
		if a16[i] != b16[i] {
			return a16[i] < b16[i]
		}
	}
	// IPs are identical, which shouldn't happen after deduction, but for completeness.
	return false
}
