// STATUS: PLATIN VGT SUPREME

package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func encodeExportTokenRaw(t *testing.T, raw []byte) string {
	t.Helper()
	return ExportTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func TestExportTokenRoundTrip(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpointAt(t, provider, 3)
	exportedAt := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	token, err := ExportToken([]Checkpoint{checkpoint}, testHostID, exportedAt)
	if err != nil {
		t.Fatalf("ExportToken: %v", err)
	}
	if !strings.HasPrefix(token, ExportTokenPrefix) {
		t.Fatalf("token prefix is missing: %.12s", token)
	}
	if len(token) > ExportMaxTokenBytes {
		t.Fatalf("token length is %d", len(token))
	}
	if strings.Contains(token, "=") {
		t.Fatal("token contains base64 padding")
	}
	again, err := ExportToken([]Checkpoint{checkpoint}, testHostID, exportedAt)
	if err != nil {
		t.Fatalf("ExportToken again: %v", err)
	}
	if token != again {
		t.Fatal("export is not deterministic")
	}
	payload, err := ImportToken(token, provider.Ed25519PublicKey())
	if err != nil {
		t.Fatalf("ImportToken: %v", err)
	}
	if payload.Schema != ExportSchema || payload.HostID != testHostID {
		t.Fatalf("payload metadata is %+v", payload)
	}
	if payload.ExportedAtUTC != exportedAt.Format(time.RFC3339) {
		t.Fatalf("payload export time is %q", payload.ExportedAtUTC)
	}
	if len(payload.Checkpoints) != 1 || payload.Checkpoints[0].CheckpointID != checkpoint.CheckpointID {
		t.Fatal("payload checkpoint does not round trip")
	}
	if err := VerifyCheckpoint(payload.Checkpoints[0], provider.Ed25519PublicKey()); err != nil {
		t.Fatalf("imported checkpoint does not verify: %v", err)
	}
}

func TestExportTokenCarriesNoPrivateKey(t *testing.T) {
	provider, privateKey := newTestKeyProvider(t)
	checkpoint := signedTestCheckpointAt(t, provider, 1)
	token, err := ExportToken([]Checkpoint{checkpoint}, testHostID, testNow())
	if err != nil {
		t.Fatalf("ExportToken: %v", err)
	}
	seed := privateKey.Seed()
	for _, representation := range []string{
		hex.EncodeToString(seed),
		base64.RawURLEncoding.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(seed),
		string(seed),
	} {
		if representation != "" && strings.Contains(token, representation) {
			t.Fatal("export token leaks private key material")
		}
	}
	if strings.Contains(strings.ToLower(token), "private") {
		t.Fatal("export token names a private key")
	}
}

func TestExportTokenSizeLimit(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	batch := []Checkpoint{
		signedTestCheckpointAt(t, provider, 1),
		signedTestCheckpointAt(t, provider, 2),
	}
	if _, err := ExportToken(batch, testHostID, testNow()); !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("oversized batch error is %v, want ErrExportTooLarge", err)
	}
	if _, err := ExportToken(nil, testHostID, testNow()); !errors.Is(err, ErrExportInvalid) {
		t.Fatalf("empty batch error is %v", err)
	}
	unsigned := testCheckpointBody()
	if _, err := ExportToken([]Checkpoint{unsigned}, testHostID, testNow()); !errors.Is(err, ErrExportInvalid) {
		t.Fatalf("unsigned checkpoint export error is %v", err)
	}
	if _, err := ExportToken([]Checkpoint{signedTestCheckpointAt(t, provider, 1)}, testHostID, time.Time{}); !errors.Is(err, ErrExportInvalid) {
		t.Fatalf("missing export time error is %v", err)
	}
}

func TestImportTokenRejections(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpointAt(t, provider, 1)
	validToken, err := ExportToken([]Checkpoint{checkpoint}, testHostID, testNow())
	if err != nil {
		t.Fatalf("ExportToken: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(validToken, ExportTokenPrefix))
	if err != nil {
		t.Fatalf("decode valid token: %v", err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}
	unknownField := append(bytes.TrimSuffix(decoded, []byte("}")), []byte(`,"unexpected":1}`)...)
	badSchema := bytes.Replace(decoded, []byte(ExportSchema), []byte("vgt-gedefense-witness-export-v2"), 1)
	zeroBatch := func() []byte {
		var payload ExportPayload
		if err := json.Unmarshal(decoded, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		payload.BatchSHA256 = strings.Repeat("00", 32)
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("encode payload: %v", err)
		}
		return raw
	}()
	emptyBatch := func() []byte {
		payload := ExportPayload{
			Schema: ExportSchema, HostID: testHostID,
			ExportedAtUTC: testNow().Format(time.RFC3339), BatchSHA256: strings.Repeat("00", 32),
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("encode payload: %v", err)
		}
		return raw
	}()
	cases := []struct {
		name  string
		token string
		key   ed25519.PublicKey
		want  error
	}{
		{"empty", "", provider.Ed25519PublicKey(), ErrExportInvalid},
		{"oversized", strings.Repeat("a", ExportMaxTokenBytes+1), provider.Ed25519PublicKey(), ErrExportTooLarge},
		{"wrong prefix", "vgtw2:" + strings.TrimPrefix(validToken, ExportTokenPrefix), provider.Ed25519PublicKey(), ErrExportInvalid},
		{"bad base64", ExportTokenPrefix + "***", provider.Ed25519PublicKey(), ErrExportInvalid},
		{"padded base64", validToken + "=", provider.Ed25519PublicKey(), ErrExportInvalid},
		{"unknown field", encodeExportTokenRaw(t, unknownField), provider.Ed25519PublicKey(), ErrExportInvalid},
		{"bad schema", encodeExportTokenRaw(t, badSchema), provider.Ed25519PublicKey(), ErrExportInvalid},
		{"bad batch digest", encodeExportTokenRaw(t, zeroBatch), provider.Ed25519PublicKey(), ErrExportInvalid},
		{"empty batch", encodeExportTokenRaw(t, emptyBatch), provider.Ed25519PublicKey(), ErrExportInvalid},
		{"wrong verification key", validToken, otherPublic, ErrExportInvalid},
		{"invalid verification key", validToken, nil, ErrExportInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ImportToken(testCase.token, testCase.key); !errors.Is(err, testCase.want) {
				t.Fatalf("ImportToken error is %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestImportTokenRejectsOversizedBatch(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoints := make([]Checkpoint, 0, ExportMaxCheckpoints+1)
	for sequence := uint64(1); sequence <= ExportMaxCheckpoints+1; sequence++ {
		checkpoints = append(checkpoints, signedTestCheckpointAt(t, provider, sequence))
	}
	digest, err := batchDigest(checkpoints)
	if err != nil {
		t.Fatalf("batchDigest: %v", err)
	}
	payload := ExportPayload{
		Schema: ExportSchema, HostID: testHostID,
		ExportedAtUTC: testNow().Format(time.RFC3339),
		BatchSHA256:   hex.EncodeToString(digest[:]), Checkpoints: checkpoints,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	if _, err := ImportToken(encodeExportTokenRaw(t, raw), provider.Ed25519PublicKey()); !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("oversized batch error is %v, want ErrExportTooLarge", err)
	}
}
