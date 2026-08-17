package cache

import (
	"strings"
	"testing"
)

// legacyNVDCachePrefix is the prefix every build up to and including M54 used.
//
// It is written out here rather than imported because the point of this file is
// to pin the relationship between the two spellings. If NVDCachePrefix is ever
// edited back to this value — or to anything that shares a prefix with it —
// TestNVDCacheKeySpaceIsDisjointFromTheLegacyOne fails.
const legacyNVDCachePrefix = "nvd:vuln:"

// TestNVDCacheKeySpaceIsDisjointFromTheLegacyOne is the executable form of the
// argument in NVDCachePrefix's doc comment.
//
// cacheKey interpolates a caller-supplied component name, and component names
// arrive from uploaded SBOMs as arbitrary byte strings. So the set of keys a
// build can construct is exactly `<its prefix> + <anything>`. Two such sets
// intersect if and only if one prefix is a prefix of the other:
//
//   - if NVDCachePrefix is a prefix of the legacy one, EVERY legacy key already
//     starts with NVDCachePrefix, so this build can read entries an old build
//     wrote for an unrelated component;
//   - if the legacy one is a prefix of NVDCachePrefix, an old build reaches any
//     key this build uses by scanning a component named after the remainder.
//
// Neither direction may hold. This is what makes the M55 digest scheme actually
// closed rather than merely differently-spelled: the digest stops collisions
// WITHIN a build, and this property stops them ACROSS builds.
func TestNVDCacheKeySpaceIsDisjointFromTheLegacyOne(t *testing.T) {
	if NVDCachePrefix == legacyNVDCachePrefix {
		t.Fatalf("NVDCachePrefix is still %q — a pre-M55 writer keys an "+
			"attacker-named component straight onto this build's digest keys",
			NVDCachePrefix)
	}

	if strings.HasPrefix(legacyNVDCachePrefix, NVDCachePrefix) {
		t.Errorf("NVDCachePrefix %q is a prefix of the legacy %q, so every key a "+
			"pre-M55 build wrote is inside this build's key space",
			NVDCachePrefix, legacyNVDCachePrefix)
	}

	if strings.HasPrefix(NVDCachePrefix, legacyNVDCachePrefix) {
		suffix := strings.TrimPrefix(NVDCachePrefix, legacyNVDCachePrefix)
		t.Errorf("NVDCachePrefix %q extends the legacy %q, so a pre-M55 build "+
			"reaches this build's keys by scanning a component whose name starts "+
			"with %q — bumping the prefix this way changes the spelling without "+
			"separating the spaces",
			NVDCachePrefix, legacyNVDCachePrefix, suffix)
	}
}

// TestNVDCacheKeyIsUnreachableFromALegacyComponentName drives the property
// through cacheKey itself rather than reasoning about the constants, so a change
// to how cacheKey composes the key (a different separator, an added segment)
// is covered too.
//
// The adversary is the one from NVDCachePrefix's doc comment: they choose the
// component name, and a pre-M55 build turns that name into `legacy + name`
// verbatim. The test asserts no such string can equal a key this build builds.
func TestNVDCacheKeyIsUnreachableFromALegacyComponentName(t *testing.T) {
	c := &NVDCache{}

	// The names an attacker would pick: the exact strings this build feeds to
	// cacheKey, plus the shapes that defeated the first two attempts at this
	// fix (raw name, and the "v2:"-style prefix extension).
	names := []string{
		"m55.0123456789abcdef",
		"openssl",
		"v2:m55.0123456789abcdef",
		"",
		":",
		"nvd:vuln:m55.0123456789abcdef",
	}

	for _, name := range names {
		for _, version := range []string{"", "1.1.1k"} {
			ours := c.cacheKey(name, version)
			if !strings.HasPrefix(ours, NVDCachePrefix) {
				t.Fatalf("cacheKey(%q, %q) = %q does not start with NVDCachePrefix %q — "+
					"the disjointness argument below assumes it does",
					name, version, ours, NVDCachePrefix)
			}

			// What a pre-M55 build writes when it scans a component called
			// `name`. It joins with a colon and escapes nothing, so this is the
			// whole of what it can produce for that name.
			legacyNoVersion := legacyNVDCachePrefix + name
			legacyWithVersion := legacyNVDCachePrefix + name + ":" + version

			if ours == legacyNoVersion || ours == legacyWithVersion {
				t.Errorf("a pre-M55 build writing component %q reaches this build's key %q — "+
					"the two key spaces are not disjoint", name, ours)
			}
		}
	}
}
