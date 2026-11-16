// STATUS: PLATIN VGT SUPREME

package witness

// Strict, bounded JSON decoding. Every external document that crosses a trust
// boundary (checkpoint, receipt, export token, outbox document) is decoded here
// or with the same rules: unknown fields are rejected, exactly one JSON value is
// accepted, trailing data is refused, top-level null fields are refused and the
// document size is capped before the decoder sees it. Decoding never repairs.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrMalformedJSON marks a document that is not exactly one strict JSON
	// object.
	ErrMalformedJSON = errors.New("document is not strict JSON")
	// ErrDocumentTooLarge marks a document above its configured byte bound.
	ErrDocumentTooLarge = errors.New("document exceeds its size bound")
)

// decodeStrictJSON decodes exactly one JSON object into dst with unknown fields
// rejected, a hard size bound and no trailing data. Null top-level fields are
// rejected because encoding/json would otherwise turn them into zero values and
// quietly "repair" a malformed document.
func decodeStrictJSON(data []byte, maxBytes int, dst any) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: document is empty", ErrMalformedJSON)
	}
	if maxBytes > 0 && len(data) > maxBytes {
		return fmt.Errorf("%w: %d > %d bytes", ErrDocumentTooLarge, len(data), maxBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedJSON, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrMalformedJSON)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedJSON, err)
	}
	for name, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%w: field %q is null", ErrMalformedJSON, name)
		}
	}
	return nil
}

// jsonLiteralMessage reports whether raw is the JSON null literal.
func jsonLiteralMessage(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
