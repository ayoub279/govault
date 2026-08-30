package middleware

import "net/http"

// SecurityHeaders sets response headers that are cheap, uncontroversial
// defaults for a JSON API — and, for this project specifically, close a real
// finding from Phase 10's OWASP ZAP baseline scan: ZAP flagged "Storable and
// Cacheable Content" on our responses (2 instances). Without an explicit
// no-store directive, a caching proxy sitting in front of this API could
// cache and later replay a response — which, for a secrets manager, might
// contain a decrypted secret value or a PASETO auth token. Every response
// this API returns is dynamic, user-specific, and frequently sensitive, so
// nothing here should ever be cached.
//
// The other headers are standard, low-cost API hygiene that ZAP's baseline
// scan (or any DAST/security scanner) commonly flags when absent, even
// though ZAP didn't happen to flag them on this run — setting them
// pre-emptively rather than waiting for a scanner to point them out.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		h.Set("Pragma", "no-cache")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
