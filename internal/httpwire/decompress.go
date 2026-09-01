package httpwire

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"
)

// DecompressResponseBody transparently decompresses gzip/deflate response
// bodies, mirroring undici fetch semantics. Bytes peeked for format detection
// are always re-attached to the body, so callers never lose data. It reports
// whether the body was decompressed.
func DecompressResponseBody(resp *http.Response) bool {
	if resp == nil || resp.Body == nil {
		return false
	}

	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding != "gzip" && encoding != "deflate" {
		return false
	}

	head := make([]byte, 2)
	n, errReadHead := io.ReadFull(resp.Body, head)
	if errReadHead != nil && !errors.Is(errReadHead, io.EOF) && !errors.Is(errReadHead, io.ErrUnexpectedEOF) {
		return false
	}

	prefix := head[:n]
	fullBodyReader := io.MultiReader(bytes.NewReader(prefix), resp.Body)

	switch encoding {
	case "gzip":
		// Gzip magic number is 0x1f 0x8b
		if len(prefix) < 2 || prefix[0] != 0x1f || prefix[1] != 0x8b {
			resp.Body = &decompressReadCloser{
				reader: fullBodyReader,
				closer: resp.Body,
			}
			return false
		}

		gzReader, errGz := gzip.NewReader(fullBodyReader)
		if errGz != nil {
			resp.Body = &decompressReadCloser{
				reader: fullBodyReader,
				closer: resp.Body,
			}
			return false
		}

		resp.Body = &decompressReadCloser{
			reader: gzReader,
			closer: resp.Body,
		}

	case "deflate":
		// RFC 1950 zlib header check:
		// CMF = prefix[0], FLG = prefix[1]
		// 1) (CMF*256 + FLG) % 31 == 0 (check bits)
		// 2) CMF & 0x0F == 8 (compression method deflate)
		// 3) CMF >> 4 <= 7 (window size log2 - 8 <= 7)
		// 4) FLG & 0x20 == 0 (no preset dictionary FDICT)
		isZlib := false
		if len(prefix) >= 2 {
			cmf := prefix[0]
			flg := prefix[1]
			if (uint16(cmf)*256+uint16(flg))%31 == 0 &&
				(cmf&0x0F) == 8 &&
				(cmf>>4) <= 7 &&
				(flg&0x20) == 0 {
				isZlib = true
			}
		}

		if isZlib {
			zReader, errZlib := zlib.NewReader(fullBodyReader)
			if errZlib != nil {
				resp.Body = &decompressReadCloser{
					reader: fullBodyReader,
					closer: resp.Body,
				}
				return false
			}
			resp.Body = &decompressReadCloser{
				reader: zReader,
				closer: resp.Body,
			}
		} else {
			fReader := flate.NewReader(fullBodyReader)
			resp.Body = &decompressReadCloser{
				reader: fReader,
				closer: resp.Body,
			}
		}
	}

	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return true
}

type decompressReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (d *decompressReadCloser) Read(p []byte) (int, error) {
	return d.reader.Read(p)
}

func (d *decompressReadCloser) Close() error {
	var errReader error
	if c, ok := d.reader.(io.Closer); ok {
		errReader = c.Close()
	}
	errCloser := d.closer.Close()
	if errReader != nil {
		return errReader
	}
	return errCloser
}
