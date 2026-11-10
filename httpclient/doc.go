// Package httpclient fetches small and large HTTP resources for repository
// clients: every body is size-capped, transient failures are retried with
// jittered exponential backoff, and files are written atomically.
//
// A Client owns one tuned connection pool and one retry policy, both set
// through Options; share one Client across goroutines. Nothing is configured
// through package-level state.
//
// Retry classification is exposed as IsRetryable: transport errors, truncated
// bodies and HTTP 408, 429 and 5xx are retried; 404, certificate failures,
// size-cap violations and context cancellation are not.
package httpclient
