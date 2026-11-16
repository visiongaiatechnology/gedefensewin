// STATUS: PLATIN VGT SUPREME
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
	"github.com/visiongaiatechnology/gedefense/windows/internal/spyware"
	"github.com/visiongaiatechnology/gedefense/windows/internal/witness"
)

const (
	maxWitnessSettingsBytes = 64 << 10
	maxPersistencePerScan   = 512
)

type witnessProvisioningDoc struct {
	SchemaVersion            int    `json:"schemaVersion"`
	Endpoint                 string `json:"endpoint"`
	SPKIPin                  string `json:"spkiPin"`
	ReceiptPublicKey         string `json:"receiptPublicKey"`
	HostID                   string `json:"hostId"`
	PolicyGeneration         uint64 `json:"policyGeneration"`
	IntervalSeconds          int    `json:"intervalSeconds,omitempty"`
	TimeoutSeconds           int    `json:"timeoutSeconds,omitempty"`
	AllowPrivateDestinations bool   `json:"allowPrivateDestinations,omitempty"`
}

type evidenceWitnessLedgerAdapter struct {
	ledger *evidence.Ledger
}

func (a evidenceWitnessLedgerAdapter) WitnessLedgerHead(ctx context.Context) (witness.LedgerHead, error) {
	if ctx != nil && ctx.Err() != nil {
		return witness.LedgerHead{}, ctx.Err()
	}
	if a.ledger == nil {
		return witness.LedgerHead{}, errors.New("evidence ledger unavailable")
	}
	records, err := a.ledger.Snapshot(1)
	if err != nil {
		return witness.LedgerHead{}, err
	}
	if len(records) == 0 {
		return witness.LedgerHead{}, witness.ErrNoNewEvidence
	}
	if err := a.ledger.Verify(); err != nil {
		return witness.LedgerHead{}, err
	}
	tip := records[len(records)-1]
	timestamp := tip.Timestamp.UTC()
	return witness.LedgerHead{
		LedgerEpoch:          1,
		Sequence:             tip.Sequence,
		TipSHA256:            strings.ToLower(strings.TrimSpace(tip.MAC)),
		SegmentFirstSequence: tip.Sequence,
		EventCount:           1,
		WindowStartUTC:       timestamp,
		WindowEndUTC:         timestamp,
	}, nil
}

func newV6SpywareEngine(ledger *evidence.Ledger) *spyware.Engine {
	return spyware.NewHostEngine(spyware.Settings{
		Enabled:     true,
		BYOVD:       true,
		Capability:  true,
		Persistence: true,
		LSASS:       true,
	}, ledger)
}

func (r *v6Runtime) stopWitness() {
	r.mu.Lock()
	engine := r.witness
	r.witness = nil
	r.mu.Unlock()
	if engine != nil {
		_ = engine.Close()
	}
}

func (r *v6Runtime) startWitness() error {
	if strings.TrimSpace(r.dataRoot) == "" || !filepath.IsAbs(r.dataRoot) {
		r.setWitnessState(witnessStateInvalid, "witness data root must be an absolute path")
		return errors.New("witness data root unavailable")
	}
	settingsPath := filepath.Join(r.dataRoot, "witness", "settings.json")
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.setWitnessState(witnessStateMissing, "witness/settings.json is not provisioned")
			return errors.New("witness provisioning file witness/settings.json is missing")
		}
		r.setWitnessState(witnessStateInvalid, "witness/settings.json could not be read: "+boundedV6Reason(err))
		return fmt.Errorf("read witness provisioning: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxWitnessSettingsBytes {
		r.setWitnessState(witnessStateInvalid, "witness/settings.json size is outside bounds")
		return errors.New("witness provisioning document size rejected")
	}

	var doc witnessProvisioningDoc
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		r.setWitnessState(witnessStateInvalid, "witness/settings.json JSON invalid")
		return errors.New("witness provisioning JSON invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		r.setWitnessState(witnessStateInvalid, "witness/settings.json contains trailing data")
		return errors.New("witness provisioning trailing data rejected")
	}
	if doc.SchemaVersion != 1 {
		r.setWitnessState(witnessStateInvalid, "witness/settings.json schemaVersion must be 1")
		return errors.New("unsupported witness provisioning schemaVersion")
	}

	receiptKey, err := decodeEd25519PublicKey(doc.ReceiptPublicKey)
	if err != nil {
		r.setWitnessState(witnessStateInvalid, "witness receipt public key invalid: "+boundedV6Reason(err))
		return err
	}

	settings, err := witness.NewSettings(witness.Settings{
		Enabled:                  true,
		Endpoint:                 doc.Endpoint,
		SPKIPin:                  doc.SPKIPin,
		ReceiptPublicKey:         receiptKey,
		HostID:                   doc.HostID,
		AgentVersion:             r.version,
		PolicyGeneration:         doc.PolicyGeneration,
		Interval:                 time.Duration(doc.IntervalSeconds) * time.Second,
		Timeout:                  time.Duration(doc.TimeoutSeconds) * time.Second,
		OutboxPath:               filepath.Join(r.dataRoot, "witness", "outbox.enc"),
		AllowPrivateDestinations: doc.AllowPrivateDestinations,
	})
	if err != nil {
		r.setWitnessState(witnessStateInvalid, "witness settings rejected: "+boundedV6Reason(err))
		return err
	}

	keysDir := filepath.Join(r.dataRoot, "witness", "keys")
	privKey, _, _, err := secretfs.LoadOrCreateEd25519Seed(filepath.Join(keysDir, "checkpoint.ed25519"))
	if err != nil {
		r.setWitnessState(witnessStateInvalid, "witness signing key unavailable: "+boundedV6Reason(err))
		return fmt.Errorf("witness signing key: %w", err)
	}
	outboxKey, err := secretfs.LoadOrCreateRawKey(filepath.Join(keysDir, "outbox.key"), 32)
	if err != nil {
		r.setWitnessState(witnessStateInvalid, "witness outbox key unavailable: "+boundedV6Reason(err))
		return fmt.Errorf("witness outbox key: %w", err)
	}
	keyProvider, err := witness.NewStaticKeyProvider(privKey, outboxKey)
	if err != nil {
		r.setWitnessState(witnessStateInvalid, "witness key provider invalid")
		return err
	}

	engine, err := witness.New(settings, keyProvider, evidenceWitnessLedgerAdapter{ledger: r.ledger})
	if err != nil {
		r.setWitnessState(witnessStateInvalid, "witness engine init failed: "+boundedV6Reason(err))
		return err
	}

	r.mu.Lock()
	old := r.witness
	r.witness = engine
	r.witnessState = witnessStateLoaded
	r.witnessReason = "witness provisioning verified and engine ready"
	running := r.running
	runCtx := r.runCtx
	r.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	if running && runCtx != nil {
		if err := engine.Start(runCtx); err != nil {
			r.setWitnessReason("witness engine could not start: " + boundedV6Reason(err))
			return err
		}
	}
	return nil
}

func decodeEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("witness receipt public key is empty")
	}
	if len(trimmed) == hex.EncodedLen(ed25519.PublicKeySize) {
		if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if decoded, err := enc.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}
	return nil, errors.New("witness receipt public key must be 32 bytes (hex or base64)")
}

func (r *v6Runtime) runCapabilitySensor(ctx context.Context) {
	ticker := time.NewTicker(v6CapabilityPollInterval)
	defer ticker.Stop()
	for {
		cfg := r.effectiveConfig()
		if cfg.SpywareEnabled && cfg.Capability {
			states, err := readHostCapabilityStates()
			locked, lockState := probeHostWorkstationLock()
			r.setLockState(lockState)
			r.noteSensorProblem("capability", err)
			if r.spyware != nil {
				r.spyware.HandleCapabilityStates(states, locked)
				r.spyware.MarkScan(time.Now().UTC())
			}
		} else {
			r.noteSensorProblem("capability", nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *v6Runtime) runDriverSensor(ctx context.Context) {
	ticker := time.NewTicker(v6DriverScanInterval)
	defer ticker.Stop()
	for {
		cfg := r.effectiveConfig()
		if cfg.SpywareEnabled && cfg.BYOVD {
			services, err := readHostDriverServices()
			posture, _ := readHostSecurityPosture()
			r.noteSensorProblem("driver", err)
			if r.spyware != nil {
				for _, svc := range services {
					if ctx.Err() != nil {
						return
					}
					r.spyware.HandleDriverService(svc, posture)
				}
				r.spyware.MarkScan(time.Now().UTC())
			}
		} else {
			r.noteSensorProblem("driver", nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *v6Runtime) runPersistenceSensor(ctx context.Context) {
	ticker := time.NewTicker(v6PersistenceScanInterval)
	defer ticker.Stop()
	for {
		cfg := r.effectiveConfig()
		if cfg.SpywareEnabled && cfg.Persistence {
			observations, err := readHostPersistenceObservations()
			r.noteSensorProblem("persistence", err)
			if r.spyware != nil {
				for _, obs := range observations {
					if ctx.Err() != nil {
						return
					}
					r.spyware.HandlePersistence(obs)
				}
				r.spyware.MarkScan(time.Now().UTC())
			}
		} else {
			r.noteSensorProblem("persistence", nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *v6Runtime) runLSASSSensor(ctx context.Context) {
	ticker := time.NewTicker(v6SensorRetryInterval)
	defer ticker.Stop()
	for {
		cfg := r.effectiveConfig()
		if cfg.SpywareEnabled && cfg.LSASS {
			events, err := pollHostLSASSAccessEvents(ctx)
			r.noteSensorProblem("lsass", err)
			if r.spyware != nil {
				for _, ev := range events {
					r.spyware.HandleLSASSAccess(ev.AccessMask, ev.CallerImage, ev.CallerSignature)
				}
				r.spyware.MarkScan(time.Now().UTC())
			}
		} else {
			r.noteSensorProblem("lsass", nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
