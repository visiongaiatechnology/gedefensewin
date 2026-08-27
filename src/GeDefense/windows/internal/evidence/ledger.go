// STATUS: DIAMANT VGT SUPREME
package evidence

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Record struct {
	Sequence    uint64    `json:"sequence"`
	Timestamp   time.Time `json:"timestamp"`
	Kind        string    `json:"kind"`
	Action      string    `json:"action"`
	Result      string    `json:"result"`
	PreviousMAC string    `json:"previous_mac"`
	MAC         string    `json:"mac"`
}

type Ledger struct {
	mu       sync.Mutex
	path     string
	key      []byte
	sequence uint64
	lastMAC  string
}

func Open(path, keyPath string) (*Ledger, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(keyPath) {
		return nil, errors.New("evidence paths must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	ledger := &Ledger{path: path, key: key}
	if err := ledger.verifyLocked(); err != nil {
		return nil, err
	}
	return ledger, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		key, decodeErr := base64.RawStdEncoding.DecodeString(string(raw))
		if decodeErr != nil || len(key) != 32 {
			return nil, errors.New("evidence key is invalid")
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.RawStdEncoding.EncodeToString(key)), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (l *Ledger) Append(kind, action, result string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	record := Record{Sequence: l.sequence + 1, Timestamp: time.Now().UTC(), Kind: kind, Action: action, Result: result, PreviousMAC: l.lastMAC}
	mac, err := l.calculate(record)
	if err != nil {
		return err
	}
	record.MAC = mac
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(append(raw, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	l.sequence, l.lastMAC = record.Sequence, record.MAC
	return nil
}

func (l *Ledger) Snapshot(limit int) ([]Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit < 1 || limit > 500 {
		return nil, errors.New("evidence limit outside boundary")
	}
	file, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Record{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	records := make([]Record, 0, limit)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, errors.New("evidence record decoding failed")
		}
		records = append(records, record)
		if len(records) > limit {
			copy(records, records[1:])
			records = records[:limit]
		}
	}
	return records, scanner.Err()
}

func (l *Ledger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.verifyLocked()
}

func (l *Ledger) verifyLocked() error {
	file, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		l.sequence, l.lastMAC = 0, ""
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var sequence uint64
	previous := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return errors.New("evidence chain contains invalid JSON")
		}
		if record.Sequence != sequence+1 || record.PreviousMAC != previous {
			return errors.New("evidence chain linkage invalid")
		}
		expected, err := l.calculate(record)
		if err != nil {
			return err
		}
		provided, providedErr := hex.DecodeString(record.MAC)
		expectedBytes, expectedErr := hex.DecodeString(expected)
		if providedErr != nil || expectedErr != nil || len(provided) != sha256.Size || !hmac.Equal(expectedBytes, provided) {
			return errors.New("evidence chain authentication failed")
		}
		sequence, previous = record.Sequence, record.MAC
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("evidence chain read: %w", err)
	}
	l.sequence, l.lastMAC = sequence, previous
	return nil
}

func (l *Ledger) calculate(record Record) (string, error) {
	record.MAC = ""
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
