package handlers

// THIS FILE IS A DELIBERATE TEST FIXTURE for verifying the dependency-scan CI
// job (govulncheck + Trivy) actually catches a real, documented CVE:
// CVE-2021-38561 / GO-2021-0113, an out-of-bounds read in
// golang.org/x/text/language's Parse, fixed in x/text v0.3.7. go.mod below is
// pinned (via a replace directive) to v0.3.6, just before the fix.
//
// vulnTestFixtureParseAcceptLanguage is never called from application code —
// it exists only so govulncheck's call-graph reachability analysis has a real
// path from this module into the vulnerable golang.org/x/text/language.Parse
// symbol, not just a version sitting unused in go.sum.
//
// This file is deleted before this branch is done being used; it must never
// be merged into main.

import (
	"net/http"

	"golang.org/x/text/language"
)

// vulnTestFixtureParseAcceptLanguage parses a client-supplied Accept-Language
// header with the vulnerable golang.org/x/text/language.Parse.
func vulnTestFixtureParseAcceptLanguage(r *http.Request) (language.Tag, error) {
	return language.Parse(r.Header.Get("Accept-Language"))
}

// init calls the fixture above so it's actually part of the module's call
// graph (an uncalled function is dead code and govulncheck's reachability
// analysis correctly ignores it — learned that the hard way while building
// this fixture). A safe, non-nil dummy request; this never runs in the real
// app, only exists for static reachability analysis to find.
func init() {
	_, _ = vulnTestFixtureParseAcceptLanguage(&http.Request{Header: make(http.Header)})
}
