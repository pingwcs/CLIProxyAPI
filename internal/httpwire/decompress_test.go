package httpwire

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"testing"
)

func TestDecompressResponseBody(t *testing.T) {
	t.Parallel()

	// 1. gzip normal decompression
	t.Run("gzip normal", func(t *testing.T) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte("hello gzip world"))
		_ = gz.Close()

		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": []string{"gzip"}, "Content-Length": []string{"100"}},
			Body:          io.NopCloser(bytes.NewReader(buf.Bytes())),
			ContentLength: 100,
		}

		if !DecompressResponseBody(resp) {
			t.Fatal("expected DecompressResponseBody to return true")
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != "hello gzip world" {
			t.Fatalf("got %q, want 'hello gzip world'", string(body))
		}
		if resp.Header.Get("Content-Encoding") != "" {
			t.Error("expected Content-Encoding to be removed")
		}
		if resp.Header.Get("Content-Length") != "" {
			t.Error("expected Content-Length to be removed")
		}
		if resp.ContentLength != -1 {
			t.Errorf("ContentLength = %d, want -1", resp.ContentLength)
		}
		if !resp.Uncompressed {
			t.Error("expected Uncompressed = true")
		}
	})

	// 2. deflate (zlib) normal decompression
	t.Run("deflate zlib normal", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write([]byte("hello zlib world"))
		_ = zw.Close()

		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": []string{"deflate"}},
			Body:          io.NopCloser(bytes.NewReader(buf.Bytes())),
			ContentLength: int64(buf.Len()),
		}

		if !DecompressResponseBody(resp) {
			t.Fatal("expected DecompressResponseBody to return true")
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != "hello zlib world" {
			t.Fatalf("got %q, want 'hello zlib world'", string(body))
		}
		if !resp.Uncompressed {
			t.Error("expected Uncompressed = true")
		}
	})

	// 3. raw deflate decompression
	t.Run("raw deflate normal", func(t *testing.T) {
		var buf bytes.Buffer
		fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		_, _ = fw.Write([]byte("hello raw deflate world"))
		_ = fw.Close()

		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": []string{"deflate"}},
			Body:          io.NopCloser(bytes.NewReader(buf.Bytes())),
			ContentLength: int64(buf.Len()),
		}

		if !DecompressResponseBody(resp) {
			t.Fatal("expected DecompressResponseBody to return true")
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != "hello raw deflate world" {
			t.Fatalf("got %q, want 'hello raw deflate world'", string(body))
		}
		if !resp.Uncompressed {
			t.Error("expected Uncompressed = true")
		}
	})

	// 4. uncompressed passthrough (no encoding or unknown encoding)
	t.Run("uncompressed passthrough", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": []string{"identity"}},
			Body:          io.NopCloser(bytes.NewReader([]byte("raw plain text"))),
			ContentLength: 14,
		}

		if DecompressResponseBody(resp) {
			t.Fatal("expected DecompressResponseBody to return false")
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != "raw plain text" {
			t.Fatalf("got %q, want 'raw plain text'", string(body))
		}
		if resp.Uncompressed {
			t.Error("expected Uncompressed = false")
		}
	})

	// 5. gzip magic number invalid: fallback passthrough without losing peeked bytes
	t.Run("gzip invalid magic passthrough without data loss", func(t *testing.T) {
		corrupted := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": []string{"gzip"}},
			Body:          io.NopCloser(bytes.NewReader(corrupted)),
			ContentLength: int64(len(corrupted)),
		}

		if DecompressResponseBody(resp) {
			t.Fatal("expected DecompressResponseBody to return false on bad gzip header")
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !bytes.Equal(body, corrupted) {
			t.Fatalf("got %v, want %v (peeked bytes must not be lost)", body, corrupted)
		}
		if resp.Uncompressed {
			t.Error("expected Uncompressed = false")
		}
	})

	// 6. Content-Encoding mixed-case and whitespace
	t.Run("Content-Encoding mixed-case and whitespace", func(t *testing.T) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte("mixed case test"))
		_ = gz.Close()

		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": []string{"  GziP  "}},
			Body:          io.NopCloser(bytes.NewReader(buf.Bytes())),
			ContentLength: int64(buf.Len()),
		}

		if !DecompressResponseBody(resp) {
			t.Fatal("expected DecompressResponseBody to return true for mixed case '  GziP  '")
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != "mixed case test" {
			t.Fatalf("got %q, want 'mixed case test'", string(body))
		}
	})

	// 7. empty body with gzip header
	t.Run("empty body with gzip header", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": []string{"gzip"}},
			Body:          io.NopCloser(bytes.NewReader([]byte{})),
			ContentLength: 0,
		}

		if DecompressResponseBody(resp) {
			t.Fatal("expected DecompressResponseBody to return false for empty body")
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if len(body) != 0 {
			t.Fatalf("expected empty body, got %d bytes", len(body))
		}
	})

	// 8. nil response or nil body
	t.Run("nil response and body safe", func(t *testing.T) {
		if DecompressResponseBody(nil) {
			t.Error("expected false for nil response")
		}
		if DecompressResponseBody(&http.Response{}) {
			t.Error("expected false for response with nil body")
		}
	})
}
