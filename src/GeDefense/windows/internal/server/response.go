// STATUS: DIAMANT VGT SUPREME
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
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

func (s *Server) newErrorID() string {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		id = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	}
	return hex.EncodeToString(id)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message, "errorId": s.newErrorID()})
}

// writeInternalError logs the engine/validation detail on the service side and
// returns only an opaque client message plus the random error id (AN-FIND-009 /
// UI-FIND-006). Client responses must never contain raw err.Error() text.
func (s *Server) writeInternalError(w http.ResponseWriter, status int, clientMessage, operation string, err error) {
	if err != nil {
		log.Printf("%s: %v", operation, err)
	}
	s.writeError(w, status, clientMessage)
}
