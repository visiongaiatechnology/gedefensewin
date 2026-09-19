// STATUS: DIAMANT VGT SUPREME
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	return decodeJSONBounded(w, r, target, 8192)
}

func decodeJSONBounded(w http.ResponseWriter, r *http.Request, target any, maximumBytes int64) error {
	if r.Body == nil || !contentTypeJSON(r) || maximumBytes < 1 || maximumBytes > 1<<20 {
		return errors.New("JSON body required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximumBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data rejected")
	}
	return nil
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(payload)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		id = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	}
	s.writeJSON(w, status, map[string]string{"error": message, "errorId": hex.EncodeToString(id)})
}
