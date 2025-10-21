// Fichier: cidr/cidr.go

package cidr

import "net"

// NetAddr represents an IP network address (CIDR) with its priority status.
type NetAddr struct {
	// IPNet is the actual network address structure.
	IPNet *net.IPNet
	// IsPriority indicates if this address came from a priority entry.
	IsPriority bool
	// OriginalPriorityIndex is used to preserve the order of user-defined priority entries
	// before numerical sorting.
	OriginalPriorityIndex int
}

// NetAddrSlice is a slice of NetAddr that implements the sort.Interface
// for customized numerical sorting (IPv4 before IPv6).
type NetAddrSlice []*NetAddr