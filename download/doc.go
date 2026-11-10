// Package download fetches files over HTTP with resume, retry, integrity
// checks and bounded concurrency, on the shared httpclient transport.
//
// Download writes to Dest+".part" and renames on success, so Dest never holds
// a partial file. A partial file from an earlier attempt or run is continued
// with a Range request guarded by If-Range; the ETag (else Last-Modified) it
// was started with is stored in Dest+".part.meta". A 200 answer (range ignored
// or file changed) restarts from zero and a 416 answer discards the partial
// and restarts once. A partial without a stored validator is never resumed.
//
// The length is checked against Content-Length or Content-Range
// (ErrBadLength, retryable after the partial is cleared), an optional digest
// is verified over the whole file including a resumed prefix
// (ErrChecksumMismatch, not retryable), and an optional size cap bounds the
// file. Progress is a plain callback; the package renders nothing.
//
// Retry classification is the single httpclient.IsRetryable: *StatusError
// (408, 429, 5xx retried, other 4xx not), transport failures and ErrBadLength
// are retried, context errors never. Retry budget and backoff are
// Options.Retry, never package state. DownloadAll runs many Requests with
// bounded concurrency and returns one Result each.
package download
