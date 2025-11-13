// Fichier: formatter/output.go

package formatter

import (
	"fmt"
	"strings"

	"project/spf-flattener/cidr"
)

const maxTXTLength = 255
const finalDirective = "~all"

// FormatSegments generates the multiple TXT records.
func FormatSegments(results cidr.NetAddrSlice, sld string) []string {
	var segments []string
	var currentSegment []string

	// Start with the SPF version
	currentLength := len("v=spf1 ")
	currentSegment = append(currentSegment, "v=spf1")

	for _, addr := range results {
		// The full SPF entry: 'ip4:X.Y.Z.W/M' or 'ip6:...'
		prefix := "ip4:"
		if addr.IPNet.IP.To4() == nil {
			prefix = "ip6:"
		}
		cidrStr := prefix + addr.IPNet.String()

		// Check if adding this CIDR would exceed limit (including space for include and ~all)
		nextIndex := len(segments) + 1
		includeStr := fmt.Sprintf("include:spf%d.%s", nextIndex, sld)
		reservedSpace := len(includeStr) + 1 // +2 for spaces

		if currentLength+len(cidrStr)+1+reservedSpace > maxTXTLength {
			// Finalize current segment with include only (no ~all)
			currentSegment = append(currentSegment, includeStr)
			segments = append(segments, strings.Join(currentSegment, " "))

			// Start new segment
			currentSegment = []string{"v=spf1", cidrStr}
			currentLength = len("v=spf1 ") + len(cidrStr) + 1
		} else {
			// Add CIDR to current segment
			currentSegment = append(currentSegment, cidrStr)
			currentLength += len(cidrStr) + 1
		}
	}

	// Finalize the last segment with just ~all
	currentSegment = append(currentSegment, finalDirective)
	segments = append(segments, strings.Join(currentSegment, " "))

	return segments
}
