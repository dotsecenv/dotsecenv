package vault

import (
	"fmt"
	"strconv"
	"strings"
)

// BinaryVersion is the dotsecenv release running this process. The dotsecenv
// binary sets it at startup. NewHeader records it, as "X.Y.Z", in every vault
// this process creates or rewrites; when it is not a release ("unknown", a bare
// commit hash, empty), nothing is recorded.
var BinaryVersion string

// parseRelease reads a release such as "0.11.0", "v0.11.0" or
// "v0.11.0-3-gabc1234-dirty" into its major, minor and patch numbers.
func parseRelease(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var release [3]int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return [3]int{}, false
		}
		release[i] = n
	}
	return release, true
}

// releaseStamp returns BinaryVersion as "X.Y.Z", or "" when it is not a release.
func releaseStamp() string {
	r, ok := parseRelease(BinaryVersion)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", r[0], r[1], r[2])
}

// IsNewerRelease reports whether release a is newer than release b. It returns
// false when either one is not a release.
func IsNewerRelease(a, b string) bool {
	ra, okA := parseRelease(a)
	rb, okB := parseRelease(b)
	if !okA || !okB {
		return false
	}
	for i := range ra {
		if ra[i] != rb[i] {
			return ra[i] > rb[i]
		}
	}
	return false
}
