// Command healthcheck is a tiny dependency-free HTTP probe used by the
// container HEALTHCHECK. The final image is distroless/static (no shell, no
// curl/wget), so the health probe must itself be a compiled binary.
//
// It performs GET http://127.0.0.1:$PORT/healthz and exits 0 on HTTP 200,
// non-zero otherwise.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: unexpected status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}
